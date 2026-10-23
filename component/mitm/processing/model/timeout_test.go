package model

import (
	"context"
	"testing"
	"time"
)

func TestTimeoutScopesReuseParentWhenItIsAlreadyEarlier(t *testing.T) {
	parent, cancelParent := WithTimeoutScope(context.Background(), time.Minute, TimeoutScopeTransaction)
	defer cancelParent()
	parentDeadline, _ := parent.Deadline()
	child, cancelChild := WithTimeoutScope(parent, time.Hour, TimeoutScopeProcessor)
	defer cancelChild()
	childDeadline, ok := child.Deadline()
	if !ok || !childDeadline.Equal(parentDeadline) || TimeoutScopeOf(child) != TimeoutScopeTransaction {
		t.Fatal("child timeout extended or replaced the earlier parent deadline")
	}
	later, cancelLater := WithDeadlineScope(parent, parentDeadline.Add(time.Second), TimeoutScopeProcessor)
	defer cancelLater()
	laterDeadline, ok := later.Deadline()
	if !ok || !laterDeadline.Equal(parentDeadline) || TimeoutScopeOf(later) != TimeoutScopeTransaction {
		t.Fatal("absolute child deadline extended or replaced its parent")
	}
}

func TestShorterTimeoutScopeBecomesEffective(t *testing.T) {
	parent, cancelParent := WithTimeoutScope(context.Background(), time.Minute, TimeoutScopeTransaction)
	defer cancelParent()
	child, cancelChild := WithTimeoutScope(parent, time.Second, TimeoutScopeProcessor)
	defer cancelChild()
	parentDeadline, _ := parent.Deadline()
	childDeadline, ok := child.Deadline()
	if !ok || !childDeadline.Before(parentDeadline) || TimeoutScopeOf(child) != TimeoutScopeProcessor {
		t.Fatal("earlier processor timeout was not recorded")
	}
}
