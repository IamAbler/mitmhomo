//go:build quickjs && cgo

#pragma GCC optimize ("wrapv")

#include "bridge.h"
#include "quickjs.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	_Atomic int requested;
} qjs_interrupt_state;

typedef struct {
	JSRuntime *runtime;
	qjs_interrupt_state *interrupt;
} qjs_runtime_handle;

typedef struct {
	JSValue value;
} qjs_compiled_script;

static int qjs_interrupt_handler(JSRuntime *runtime, void *opaque) {
	qjs_interrupt_state *state = opaque;
	(void)runtime;
	return atomic_load_explicit(&state->requested, memory_order_relaxed) != 0;
}

static char *qjs_copy_bytes(const char *source, size_t length, size_t *copy_length) {
	char *copy;
	if (length == SIZE_MAX)
		return NULL;
	copy = malloc(length + 1);
	if (!copy)
		return NULL;
	if (length)
		memcpy(copy, source, length);
	copy[length] = '\0';
	*copy_length = length;
	return copy;
}

static char *qjs_copy_value_string(JSContext *context, JSValueConst value, size_t *length) {
	const char *text;
	size_t text_length = 0;
	char *copy;
	text = JS_ToCStringLen2(context, &text_length, value, 0);
	if (!text)
		return NULL;
	copy = qjs_copy_bytes(text, text_length, length);
	JS_FreeCString(context, text);
	return copy;
}

static char *qjs_exception_message(JSContext *context, JSValue exception, size_t *length) {
	char *message = qjs_copy_value_string(context, exception, length);
	JS_FreeValue(context, exception);
	if (message)
		return message;
	if (JS_HasException(context))
		JS_FreeValue(context, JS_GetException(context));
	return qjs_copy_bytes("QuickJS exception (message conversion failed)",
			      sizeof("QuickJS exception (message conversion failed)") - 1, length);
}

static qjs_eval_result qjs_result_error(int status, char *error, size_t error_len) {
	qjs_eval_result result = {0};
	result.status = status;
	result.error = error;
	result.error_len = error_len;
	return result;
}

static qjs_eval_result qjs_result_from_value(JSContext *context, JSValue value) {
	qjs_eval_result result = {0};
	result.value = qjs_copy_value_string(context, value, &result.value_len);
	JS_FreeValue(context, value);
	if (result.value) {
		result.status = 0;
		return result;
	}
	if (JS_HasException(context)) {
		char *error = qjs_exception_message(context, JS_GetException(context), &result.error_len);
		return qjs_result_error(1, error, result.error_len);
	}
	return qjs_result_error(-1, NULL, 0);
}

void *qjs_runtime_new(size_t memory_limit, size_t stack_limit) {
	qjs_runtime_handle *handle = calloc(1, sizeof(*handle));
	qjs_interrupt_state *state;
	if (!handle)
		return NULL;
	handle->runtime = JS_NewRuntime();
	if (!handle->runtime) {
		free(handle);
		return NULL;
	}
	state = calloc(1, sizeof(*state));
	if (!state) {
		JS_FreeRuntime(handle->runtime);
		free(handle);
		return NULL;
	}
	atomic_init(&state->requested, 0);
	if (memory_limit)
		JS_SetMemoryLimit(handle->runtime, memory_limit);
	if (stack_limit)
		JS_SetMaxStackSize(handle->runtime, stack_limit);
	JS_SetInterruptHandler(handle->runtime, qjs_interrupt_handler, state);
	handle->interrupt = state;
	return handle;
}

void qjs_runtime_free(void *runtime_ptr) {
	qjs_runtime_handle *handle = runtime_ptr;
	if (handle) {
		JS_SetInterruptHandler(handle->runtime, NULL, NULL);
		JS_FreeRuntime(handle->runtime);
		free(handle->interrupt);
		free(handle);
	}
}

void qjs_runtime_set_memory_limit(void *runtime, size_t limit) {
	qjs_runtime_handle *handle = runtime;
	JS_SetMemoryLimit(handle->runtime, limit);
}

void qjs_runtime_set_max_stack_size(void *runtime, size_t limit) {
	qjs_runtime_handle *handle = runtime;
	JS_SetMaxStackSize(handle->runtime, limit);
}

uint64_t qjs_runtime_memory_usage(void *runtime) {
	qjs_runtime_handle *handle = runtime;
	JSMemoryUsage usage;
	JS_ComputeMemoryUsage(handle->runtime, &usage);
	return usage.malloc_size < 0 ? 0 : (uint64_t)usage.malloc_size;
}

int qjs_runtime_has_pending_job(void *runtime) {
	qjs_runtime_handle *handle = runtime;
	return JS_IsJobPending(handle->runtime);
}

int qjs_runtime_execute_pending_job(void *runtime, char **error, size_t *error_len) {
	qjs_runtime_handle *handle = runtime;
	JSContext *context = NULL;
	JS_UpdateStackTop(handle->runtime);
	int result = JS_ExecutePendingJob(handle->runtime, &context);
	*error = NULL;
	*error_len = 0;
	if (result < 0) {
		if (context && JS_HasException(context))
			*error = qjs_exception_message(context, JS_GetException(context), error_len);
		else
			*error = qjs_copy_bytes("QuickJS pending job failed without a live Context",
						sizeof("QuickJS pending job failed without a live Context") - 1, error_len);
	}
	return result;
}

void *qjs_context_new(void *runtime) {
	qjs_runtime_handle *handle = runtime;
	return JS_NewContext(handle->runtime);
}

void qjs_context_free(void *context) {
	JS_FreeContext(context);
}

static void qjs_eval_internal(JSContext *context, const char *source,
				      size_t source_len, int compile_only,
				      void **compiled, qjs_eval_result *result) {
	JS_UpdateStackTop(JS_GetRuntime(context));
	JSValue value = JS_Eval(context, source, source_len, "<quickjs-cgo>",
				compile_only ? JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_COMPILE_ONLY : JS_EVAL_TYPE_GLOBAL);
	if (JS_IsException(value)) {
		result->status = 1;
		result->error = qjs_exception_message(context, JS_GetException(context), &result->error_len);
		return;
	}
	if (compile_only) {
		qjs_compiled_script *script = malloc(sizeof(*script));
		if (!script) {
			JS_FreeValue(context, value);
			result->status = -1;
			return;
		}
		script->value = value;
		*compiled = script;
		result->status = 0;
		result->value = qjs_copy_bytes("compiled", 8, &result->value_len);
		if (!result->value) {
			JS_FreeValue(context, script->value);
			free(script);
			*compiled = NULL;
			result->status = -1;
		}
		return;
	}
	*result = qjs_result_from_value(context, value);
}

void qjs_context_eval(void *context, const char *source, size_t source_len, qjs_eval_result *result) {
	qjs_eval_internal(context, source, source_len, 0, NULL, result);
}

void qjs_context_compile(void *context, const char *source, size_t source_len, void **compiled, qjs_eval_result *result) {
	*compiled = NULL;
	qjs_eval_internal(context, source, source_len, 1, compiled, result);
}

void qjs_context_run_compiled(void *context, void *compiled_ptr, qjs_eval_result *result) {
	JS_UpdateStackTop(JS_GetRuntime(context));
	qjs_compiled_script *script = compiled_ptr;
	JSValue value = JS_EvalFunction(context, JS_DupValue(context, script->value));
	*result = qjs_result_from_value(context, value);
}

void qjs_compiled_free(void *context, void *compiled_ptr) {
	qjs_compiled_script *script = compiled_ptr;
	if (!script)
		return;
	JS_FreeValue(context, script->value);
	free(script);
}

static JSValue qjs_throwing_job(JSContext *context, int argc, JSValueConst *argv) {
	(void)argc;
	return JS_Throw(context, JS_DupValue(context, argv[0]));
}

int qjs_context_enqueue_throwing_job(void *context_ptr, const char *message, size_t message_len) {
	JSContext *context = context_ptr;
	JSValue value = JS_NewStringLen(context, message, message_len);
	int result;
	if (JS_IsException(value)) {
		JS_FreeValue(context, JS_GetException(context));
		return -1;
	}
	result = JS_EnqueueJob(context, qjs_throwing_job, 1, (JSValueConst *)&value);
	JS_FreeValue(context, value);
	return result;
}

void qjs_interrupt_reset(void *runtime_ptr) {
	qjs_runtime_handle *handle = runtime_ptr;
	atomic_store_explicit(&handle->interrupt->requested, 0, memory_order_relaxed);
}

void qjs_interrupt_request(void *runtime_ptr) {
	qjs_runtime_handle *handle = runtime_ptr;
	atomic_store_explicit(&handle->interrupt->requested, 1, memory_order_relaxed);
}

void qjs_buffer_free(void *buffer) {
	free(buffer);
}
