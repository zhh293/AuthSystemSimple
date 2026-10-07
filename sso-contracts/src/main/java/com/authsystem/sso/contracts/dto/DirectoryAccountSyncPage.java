package com.authsystem.sso.contracts.dto;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/** One bounded page of source changes with an opaque continuation cursor. */
public class DirectoryAccountSyncPage implements Serializable {
    @Serial private static final long serialVersionUID = 1L;
    private List<DirectoryAccountRecord> accounts = new ArrayList<>();
    private String nextCursor;
    private boolean hasMore;

    public DirectoryAccountSyncPage() { }
    public DirectoryAccountSyncPage(List<DirectoryAccountRecord> accounts, String nextCursor, boolean hasMore) {
        setAccounts(accounts);
        this.nextCursor = nextCursor;
        this.hasMore = hasMore;
    }
    public List<DirectoryAccountRecord> getAccounts() { return accounts; }
    public void setAccounts(List<DirectoryAccountRecord> accounts) {
        this.accounts = accounts == null ? null : new ArrayList<>(accounts);
    }
    public String getNextCursor() { return nextCursor; }
    public void setNextCursor(String nextCursor) { this.nextCursor = nextCursor; }
    public boolean isHasMore() { return hasMore; }
    public void setHasMore(boolean hasMore) { this.hasMore = hasMore; }

    @Override public String toString() {
        return "DirectoryAccountSyncPage{accountCount=" + (accounts == null ? "invalid" : accounts.size()) + ", cursor=[REDACTED]}";
    }
}
