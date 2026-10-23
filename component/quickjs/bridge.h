#ifndef MITMHOMO_QUICKJS_BRIDGE_H
#define MITMHOMO_QUICKJS_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
	int status;
	char *value;
	size_t value_len;
	char *error;
	size_t error_len;
} qjs_eval_result;

void *qjs_runtime_new(size_t memory_limit, size_t stack_limit);
void qjs_runtime_free(void *runtime);
void qjs_runtime_set_memory_limit(void *runtime, size_t limit);
void qjs_runtime_set_max_stack_size(void *runtime, size_t limit);
uint64_t qjs_runtime_memory_usage(void *runtime);
int qjs_runtime_has_pending_job(void *runtime);
int qjs_runtime_execute_pending_job(void *runtime, char **error, size_t *error_len);

void *qjs_context_new(void *runtime);
void qjs_context_free(void *context);
void qjs_context_eval(void *context, const char *source, size_t source_len, qjs_eval_result *result);
void qjs_context_compile(void *context, const char *source, size_t source_len, void **compiled, qjs_eval_result *result);
void qjs_context_run_compiled(void *context, void *compiled, qjs_eval_result *result);
void qjs_compiled_free(void *context, void *compiled);
int qjs_context_enqueue_throwing_job(void *context, const char *message, size_t message_len);

void qjs_interrupt_reset(void *runtime);
void qjs_interrupt_request(void *runtime);
void qjs_buffer_free(void *buffer);

#endif
