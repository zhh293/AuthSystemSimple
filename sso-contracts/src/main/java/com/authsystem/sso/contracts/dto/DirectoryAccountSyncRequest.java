package com.authsystem.sso.contracts.dto;

import java.io.Serial;
import java.io.Serializable;

/** Null cursor requests the provider's initial page. Cursor content is opaque and redacted. */
public class DirectoryAccountSyncRequest implements Serializable {
    @Serial private static final long serialVersionUID = 1L;
    private String cursor;
    private int pageSize;

    public DirectoryAccountSyncRequest() { this.pageSize = 500; }
    public DirectoryAccountSyncRequest(String cursor, int pageSize) { this.cursor = cursor; this.pageSize = pageSize; }
    public String getCursor() { return cursor; }
    public void setCursor(String cursor) { this.cursor = cursor; }
    public int getPageSize() { return pageSize; }
    public void setPageSize(int pageSize) { this.pageSize = pageSize; }

    @Override public String toString() { return "DirectoryAccountSyncRequest{cursor=[REDACTED], pageSize=" + pageSize + "}"; }
}
