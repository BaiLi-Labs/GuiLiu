package store

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func newTestStore(t *testing.T) *SQLite {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func testAccount(name string) *model.Account {
	return &model.Account{
		Name:                name,
		Provider:            "tencent",
		AccountUID:          "1234567890",
		Region:              "ap-guangzhou",
		Enabled:             true,
		Options:             map[string]string{"page_size": "100"},
		CredentialEncrypted: "ciphertext",
		AccessKeyHint:       "****abcd",
		CredentialSet:       true,
	}
}

func testAlert(title string) *model.AlertRecord {
	now := time.Date(2026, 10, 20, 6, 0, 0, 0, time.UTC)
	return &model.AlertRecord{
		Provider:    "tencent",
		AccountID:   "acct",
		AccountName: "prod",
		AccountUID:  "1234567890",
		Alert: model.Alert{
			ExternalID:    "alert-1",
			Title:         title,
			Description:   "reverse shell",
			Severity:      model.SeverityHigh,
			EventTime:     now,
			FirstSeenAt:   now.Add(-time.Hour),
			LastSeenAt:    now,
			Product:       "CWP",
			AlertType:     "MaliciousProcess",
			SourceIP:      "203.0.113.9",
			DestinationIP: "10.0.0.5",
			Resource:      model.Resource{ID: "ins-1", Name: "web-01", Type: "host"},
			Raw:           json.RawMessage(`{"ID":"alert-1"}`),
			OCSF:          json.RawMessage(`{"class_uid":2004}`),
		},
		Status: model.StatusOpen,
	}
}

func TestAlertGroupsKeepOriginalMembers(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 20, 6, 0, 0, 0, time.UTC)

	makeAlert := func(id, sourceIP string, severity model.Severity, at time.Time) *model.AlertRecord {
		a := testAlert("grouped " + id)
		a.ExternalID = id
		a.RuleID = "native-rule-1"
		a.Region = "ap-guangzhou"
		a.Severity = severity
		a.EventTime = at
		a.FirstSeenAt = at
		a.LastSeenAt = at
		a.SourceIP = sourceIP
		a.Raw = json.RawMessage(`{"ID":"` + id + `"}`)
		return a
	}
	alerts := []*model.AlertRecord{
		makeAlert("a-1", "203.0.113.10", model.SeverityHigh, base),
		makeAlert("a-2", "203.0.113.10", model.SeverityMedium, base.Add(time.Minute)),
		makeAlert("a-3", "203.0.113.11", model.SeverityLow, base.Add(2*time.Minute)),
		makeAlert("a-4", "", model.SeverityCritical, base.Add(3*time.Minute)),
	}
	for _, a := range alerts {
		if _, err := st.UpsertAlert(ctx, a); err != nil {
			t.Fatal(err)
		}
	}

	groups, total, err := st.ListAlertGroups(ctx, model.AlertFilter{GroupBy: model.GroupBySignature, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(groups) != 3 {
		t.Fatalf("signature groups total=%d groups=%+v", total, groups)
	}
	var repeated *model.AlertGroup
	for i := range groups {
		if groups[i].FindingCount == 2 {
			repeated = &groups[i]
		}
	}
	if repeated == nil || repeated.Key["source_ip"] != "203.0.113.10" || repeated.MaxSeverity != model.SeverityHigh {
		t.Fatalf("repeated group = %+v", repeated)
	}
	if repeated.ID == "" || repeated.FirstSeenAt.IsZero() || repeated.LastSeenAt.IsZero() {
		t.Fatalf("group metadata = %+v", repeated)
	}

	members, memberTotal, err := st.ListAlerts(ctx, model.AlertFilter{
		GroupBy: model.GroupBySignature, GroupKey: repeated.Key, Limit: 10,
	})
	if err != nil || memberTotal != 2 || len(members) != 2 {
		t.Fatalf("members total=%d items=%d err=%v", memberTotal, len(members), err)
	}

	assetGroups, assetTotal, err := st.ListAlertGroups(ctx, model.AlertFilter{GroupBy: model.GroupByAsset, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if assetTotal != 1 || len(assetGroups) != 1 || assetGroups[0].FindingCount != 4 {
		t.Fatalf("asset groups total=%d groups=%+v", assetTotal, assetGroups)
	}

	// Missing source IP must not merge all incomplete alerts into one group.
	var singleton *model.AlertGroup
	for i := range groups {
		if groups[i].Key["singleton"] != "" {
			singleton = &groups[i]
			break
		}
	}
	if singleton == nil || singleton.FindingCount != 1 {
		t.Fatalf("singleton group = %+v", singleton)
	}
	singletonMembers, singletonTotal, err := st.ListAlerts(ctx, model.AlertFilter{
		GroupBy: model.GroupBySignature, GroupKey: singleton.Key, Limit: 10,
	})
	if err != nil || singletonTotal != 1 || len(singletonMembers) != 1 || singletonMembers[0].ExternalID != "a-4" {
		t.Fatalf("singleton members total=%d items=%+v err=%v", singletonTotal, singletonMembers, err)
	}
}

func TestAlertRevisionsCaptureOnlySubstantiveChanges(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	first := testAlert("v1")
	if created, err := st.UpsertAlert(ctx, first); err != nil || !created {
		t.Fatalf("insert: created=%v err=%v", created, err)
	}
	revs, err := st.ListAlertRevisions(ctx, first.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) != 1 || revs[0].Revision != 1 || revs[0].Title != "v1" {
		t.Fatalf("initial revisions = %+v", revs)
	}

	// Identical re-sync must not create history noise.
	again := testAlert("v1")
	if _, err := st.UpsertAlert(ctx, again); err != nil {
		t.Fatal(err)
	}
	revs, _ = st.ListAlertRevisions(ctx, first.ID, 10)
	if len(revs) != 1 {
		t.Fatalf("identical sync created revision: %+v", revs)
	}

	changed := testAlert("v2")
	changed.Severity = model.SeverityCritical
	changed.Raw = json.RawMessage(`{"ID":"alert-1","updated":true}`)
	changed.OCSF = json.RawMessage(`{"class_uid":2004,"severity_id":5}`)
	if _, err := st.UpsertAlert(ctx, changed); err != nil {
		t.Fatal(err)
	}
	revs, _ = st.ListAlertRevisions(ctx, first.ID, 10)
	if len(revs) != 2 {
		t.Fatalf("changed sync revisions = %+v", revs)
	}
	if revs[0].Revision != 2 || revs[0].Title != "v2" || revs[0].Severity != model.SeverityCritical ||
		!strings.Contains(string(revs[0].Raw), "updated") {
		t.Fatalf("latest revision = %+v", revs[0])
	}

	// Platform status updates are not vendor revisions.
	if err := st.UpdateAlertStatus(ctx, first.ID, model.StatusAcknowledged); err != nil {
		t.Fatal(err)
	}
	revs, _ = st.ListAlertRevisions(ctx, first.ID, 10)
	if len(revs) != 2 {
		t.Fatalf("status update created revision: %+v", revs)
	}
}

func TestAccountLifecycle(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	acct := testAccount("prod")
	if err := st.CreateAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	if acct.ID == "" {
		t.Fatal("expected generated id")
	}
	if err := st.CreateAccount(ctx, testAccount("prod")); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate name error = %v", err)
	}
	got, err := st.GetAccount(ctx, acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "prod" || got.Options["page_size"] != "100" || !got.Enabled {
		t.Fatalf("account = %+v", got)
	}
	if got.CredentialEncrypted != "ciphertext" {
		t.Fatal("credential not loaded for internal use")
	}

	accounts, err := st.ListAccounts(ctx)
	if err != nil || len(accounts) != 1 {
		t.Fatalf("list accounts = %v, %v", accounts, err)
	}
	if accounts[0].CredentialEncrypted != "" {
		t.Fatal("list must not expose encrypted credentials")
	}

	blob, err := st.AccountCredential(ctx, acct.ID)
	if err != nil || blob != "ciphertext" {
		t.Fatalf("credential = %q, %v", blob, err)
	}

	got.Enabled = false
	if err := st.UpdateAccount(ctx, got, nil); err != nil {
		t.Fatal(err)
	}
	got2, _ := st.GetAccount(ctx, acct.ID)
	if got2.Enabled {
		t.Fatal("enabled flag not persisted")
	}

	if err := st.DeleteAccount(ctx, acct.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetAccount(ctx, acct.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestAlertUpsertAndQuery(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	acct := testAccount("prod")
	if err := st.CreateAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	first := testAlert("Reverse shell")
	first.AccountID = acct.ID
	created, err := st.UpsertAlert(ctx, first)
	if err != nil || !created {
		t.Fatalf("insert: created=%v err=%v", created, err)
	}

	updated := testAlert("Reverse shell (updated)")
	updated.AccountID = acct.ID
	updated.Severity = model.SeverityCritical
	created, err = st.UpsertAlert(ctx, updated)
	if err != nil || created {
		t.Fatalf("update: created=%v err=%v", created, err)
	}

	items, total, err := st.ListAlerts(ctx, model.AlertFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("total=%d items=%d", total, len(items))
	}
	if items[0].Title != "Reverse shell (updated)" || items[0].Severity != model.SeverityCritical {
		t.Fatalf("alert = %+v", items[0])
	}
	if len(items[0].OCSF) != 0 || len(items[0].Raw) != 0 {
		t.Fatal("list queries must not load payloads")
	}

	if err := st.UpdateAlertStatus(ctx, items[0].ID, model.StatusAcknowledged); err != nil {
		t.Fatal(err)
	}
	// Re-syncing must not overwrite the analyst-set status.
	created, err = st.UpsertAlert(ctx, updated)
	if err != nil || created {
		t.Fatalf("re-upsert: created=%v err=%v", created, err)
	}
	detail, err := st.GetAlert(ctx, items[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Status != model.StatusAcknowledged {
		t.Fatalf("status = %q", detail.Status)
	}
	if len(detail.OCSF) == 0 || len(detail.Raw) == 0 {
		t.Fatal("detail must include payloads")
	}

	sev := model.SeverityCritical
	now := time.Date(2026, 10, 20, 7, 0, 0, 0, time.UTC)
	found, _, err := st.ListAlerts(ctx, model.AlertFilter{
		Severities: []model.Severity{sev},
		IP:         "203.0.113.9",
		Keyword:    "updated",
		Start:      &now,
		Limit:      10,
	})
	if err != nil || len(found) != 0 { // start is after event time
		t.Fatalf("time filter: %v, %v", found, err)
	}
	yesterday := now.Add(-24 * time.Hour)
	found, _, err = st.ListAlerts(ctx, model.AlertFilter{
		Severities: []model.Severity{sev},
		IP:         "203.0.113.9",
		Keyword:    "updated",
		Start:      &yesterday,
		Limit:      10,
	})
	if err != nil || len(found) != 1 {
		t.Fatalf("expected one match, got %v (%v)", found, err)
	}

	stats, err := st.AlertStats(ctx, model.AlertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 1 || stats.BySeverity["critical"] != 1 || stats.ByProvider["tencent"] != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if len(stats.TopResources) != 1 || stats.TopResources[0].Key != "ins-1" {
		t.Fatalf("top resources = %+v", stats.TopResources)
	}

	pendingStart := now.Add(-2 * time.Hour)
	if err := st.SaveSyncState(ctx, &model.SyncState{
		AccountID:    acct.ID,
		CursorEnd:    now,
		PendingStart: pendingStart,
		PendingEnd:   now,
		PendingToken: "42",
		ItemsLastRun: 3,
	}); err != nil {
		t.Fatal(err)
	}
	state, err := st.GetSyncState(ctx, acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !state.CursorEnd.Equal(now) || state.ItemsLastRun != 3 {
		t.Fatalf("sync state = %+v", state)
	}
	if state.PendingToken != "42" || !state.PendingStart.Equal(pendingStart) || !state.PendingEnd.Equal(now) {
		t.Fatalf("pending state = %+v", state)
	}
}

func TestSyncRuns(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	run := &model.SyncRun{AccountID: "acct", Provider: "tencent", Trigger: "manual", StartedAt: now}
	if err := st.StartSyncRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	run.Status = "success"
	run.Fetched = 10
	run.Created = 8
	run.Failed = 2
	finish := now.Add(2 * time.Second)
	run.FinishedAt = &finish
	run.DurationMS = 2000
	if err := st.FinishSyncRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	runs, err := st.ListSyncRuns(ctx, "acct", 10)
	if err != nil || len(runs) != 1 {
		t.Fatalf("runs = %v, %v", runs, err)
	}
	if runs[0].Status != "success" || runs[0].Created != 8 || runs[0].FinishedAt == nil {
		t.Fatalf("run = %+v", runs[0])
	}
}

func TestQueriesFindSecondaryIndicatorsAndCorrectedTimes(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	a := testAlert("multiple indicators")
	a.Observables = []model.Observable{
		{TypeID: 2, Value: "203.0.113.99"},
		{TypeID: 10, Value: "secondary-resource"},
		{TypeID: 38, Value: "secondary-web-host"},
		{TypeID: 7, Value: "203.0.113.88"},
	}
	if _, err := st.UpsertAlert(ctx, a); err != nil {
		t.Fatal(err)
	}
	for _, f := range []model.AlertFilter{{IP: "203.0.113.99"}, {Resource: "secondary-resource"}, {Resource: "secondary-web"}} {
		items, _, err := st.ListAlerts(ctx, f)
		if err != nil || len(items) != 1 {
			t.Fatalf("filter=%+v items=%d err=%v", f, len(items), err)
		}
	}
	items, _, err := st.ListAlerts(ctx, model.AlertFilter{IP: "203.0.113.88"})
	if err != nil || len(items) != 0 {
		t.Fatal("non-IP observable matched IP query")
	}
	corrected := a.EventTime.Add(-8 * time.Hour)
	a.EventTime, a.FirstSeenAt, a.LastSeenAt = corrected, corrected, corrected
	if _, err := st.UpsertAlert(ctx, a); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetAlert(ctx, a.ID)
	if err != nil || !got.EventTime.Equal(corrected) || !got.LastSeenAt.Equal(corrected) {
		t.Fatalf("corrected timestamps=%+v err=%v", got, err)
	}
}

func TestIngestFailuresAreDurableAndDeduplicated(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	acct := testAccount("failure-test")
	if err := st.CreateAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	f := &model.IngestFailure{AccountID: acct.ID, Raw: json.RawMessage(`{"bad":true}`), IngestedAt: time.Now().UTC(), MapperVersion: "v1", Error: "bad mapping"}
	if err := st.SaveIngestFailure(ctx, f); err != nil {
		t.Fatal(err)
	}
	f.ID = ""
	if err := st.SaveIngestFailure(ctx, f); err != nil {
		t.Fatal(err)
	}
	items, total, err := st.ListIngestFailures(ctx, acct.ID, 100)
	if err != nil || total != 1 || len(items) != 1 || items[0].Attempts != 2 || string(items[0].Raw) != string(f.Raw) {
		t.Fatalf("items=%+v total=%d err=%v", items, total, err)
	}
	state, err := st.GetSyncState(ctx, acct.ID)
	if err != nil || state.FailedRecords != 1 {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	if err := st.DeleteAccount(ctx, acct.ID); err != nil {
		t.Fatal(err)
	}
	_, total, err = st.ListIngestFailures(ctx, acct.ID, 100)
	if err != nil || total != 0 {
		t.Fatalf("orphaned failures=%d err=%v", total, err)
	}
}
