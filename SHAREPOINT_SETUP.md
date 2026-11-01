# OSV Portal SharePoint Automatic Sync Setup

## What this update does

Every insert, edit, assignment/check-out, test start, pass, fail, not-tested result, transfer, release, note, reopen, import, and deletion affecting the `tickets` table is captured automatically by SQLite triggers. A background worker sends the latest ticket snapshot to a SharePoint list through Microsoft Graph.

The web transaction does **not** wait for SharePoint. The portal saves locally first, then synchronizes. If SharePoint or the network is unavailable, the item stays in a local outbox and retries with increasing delays. This prevents SharePoint from slowing or breaking the technician workflow.

## Files in this update

Copy these paths over the matching project paths:

- `mrs_app/core.py`
- `mrs_app/sharepoint_sync.py`
- `mrs_app/sharepoint_config.example.json`
- `mrs_app/check_sharepoint_sync.py`

Do not place the real client secret in source control or in a shared ZIP.

## 1. Create the SharePoint list

1. Open the target SharePoint **site**, not a page URL ending in `.aspx`.
2. Select **Site contents** > **New** > **List** > **Blank list**.
3. Name the list `OSV MRS Ticket Sync`.
4. Keep the default `Title` column.
5. Add the columns below. Enter each name exactly as shown, with no spaces. The sync uses the SharePoint **internal name**, so exact names are important.

Create these as **Single line of text**:

- `LocalTicketId`
- `StockCode`
- `MRSTicket`
- `SerialNumber`
- `Status`
- `AssignedToUserId`
- `AssignedAt`
- `TechnicianName`
- `TestStartedAt`
- `TestResult`
- `FailureReason`
- `CompletedAt`
- `CreatedAt`
- `WHLocation`
- `PartType`
- `ReturnTime`
- `QualityDisposition`
- `LogsUploaded`
- `LogPath`
- `LastSyncedUtc`

Create these as **Multiple lines of text, plain text**:

- `MRSComments`
- `PartDescription`

Create this as **Number, 0 decimal places**:

- `TransferCount`

For faster upserts, open `LocalTicketId` column settings and enable **Enforce unique values**. SharePoint may automatically index it when uniqueness is enabled.

## 2. Register the unattended application in Microsoft Entra ID

Tenant ID and primary domain are not enough by themselves. You also need an application/client ID and a credential.

1. Open Microsoft Entra admin center.
2. Go to **Identity** > **Applications** > **App registrations** > **New registration**.
3. Name it `OSV Portal SharePoint Sync`.
4. Use **Accounts in this organizational directory only**.
5. Register it and record:
   - **Directory (tenant) ID**
   - **Application (client) ID**
6. Open **Certificates & secrets** > **Client secrets** > **New client secret**.
7. Copy the **secret Value immediately**. Do not use the Secret ID.

For production, a certificate is stronger than a long-lived client secret. This package uses a client secret because it is the most direct deployment for the current Python host.

## 3. Add Microsoft Graph permission

### Recommended least-privilege option

1. In the app registration, open **API permissions**.
2. Select **Add a permission** > **Microsoft Graph** > **Application permissions**.
3. Add `Sites.Selected`.
4. Have a tenant administrator select **Grant admin consent**.
5. Separately grant this application `write` access to only the target SharePoint site. `Sites.Selected` grants no site access until this explicit assignment is made.

An administrator can make the site grant with Microsoft Graph:

`POST https://graph.microsoft.com/v1.0/sites/{SITE-ID}/permissions`

Request body:

```json
{
  "roles": ["write"],
  "grantedToIdentities": [
    {
      "application": {
        "id": "YOUR-APPLICATION-CLIENT-ID",
        "displayName": "OSV Portal SharePoint Sync"
      }
    }
  ]
}
```

The administrator performing that one-time grant needs sufficient SharePoint/Graph administrative rights.

### Simpler but broad option

Use Microsoft Graph **Application** permission `Sites.ReadWrite.All`, then grant admin consent. This avoids the separate site assignment, but it gives the application write access across all SharePoint sites in the tenant. Use this only if your security team approves it.

## 4. Get the Site ID and List ID

The SharePoint site URL should look like:

`https://contoso.sharepoint.com/sites/OSV`

It should not include `/Forms/AllItems.aspx`, `SitePages`, or another `.aspx` page.

Using Microsoft Graph Explorer or another authorized Graph client:

1. Resolve the site:

   `GET https://graph.microsoft.com/v1.0/sites/contoso.sharepoint.com:/sites/OSV`

   Copy the returned `id` value. This is the `site_id`.

2. List the site's lists:

   `GET https://graph.microsoft.com/v1.0/sites/{SITE-ID}/lists?$select=id,displayName`

   Find `OSV MRS Ticket Sync` and copy its `id`. This is the `list_id`.

## 5. Create the local configuration

1. Copy:

   `mrs_app/sharepoint_config.example.json`

   to:

   `data/sharepoint_config.json`

2. Fill in the real values:

```json
{
  "enabled": true,
  "tenant_id": "YOUR-TENANT-GUID",
  "primary_domain": "contoso.onmicrosoft.com",
  "client_id": "YOUR-APP-CLIENT-ID",
  "client_secret": "YOUR-CLIENT-SECRET-VALUE",
  "site_id": "contoso.sharepoint.com,SITE-COLLECTION-GUID,WEB-GUID",
  "list_id": "YOUR-LIST-GUID",
  "poll_seconds": 3,
  "max_attempts": 12
}
```

Protect `data/sharepoint_config.json` so only the Windows account running the portal can read it. Do not upload it to SharePoint, email it, or commit it to Git.

If you prefer to keep the config outside the project folder, set this environment variable before launching the portal:

```powershell
$env:MRS_SHAREPOINT_CONFIG = "C:\secure\sharepoint_config.json"
```

## 6. Validate before starting the portal

From the project root:

```powershell
python .\mrs_app\check_sharepoint_sync.py
```

Expected output:

- Token acquired
- SharePoint list readable
- All internal columns found
- Prerequisites passed

If it reports missing columns, create them with the exact names shown. If it reports HTTP 403, check admin consent and the `Sites.Selected` site permission assignment.

## 7. Start and test the portal

1. Start the web app normally.
2. Confirm the console prints `SharePoint sync enabled`.
3. In the portal:
   - claim/check out an MRS ticket;
   - start the test;
   - finish it as Pass or Fail.
4. Refresh the SharePoint list after several seconds.
5. Verify the same list item is updated through each stage rather than creating duplicates.

## 8. Monitoring and recovery

The update adds these SQLite tables:

- `sharepoint_sync_outbox`: pending, completed, and retry state
- `sharepoint_sync_state`: local ticket ID to SharePoint item ID mapping

Useful checks:

```sql
SELECT ticket_id, operation, attempts, last_error, synced_at
FROM sharepoint_sync_outbox
WHERE synced_at IS NULL;
```

```sql
SELECT ticket_id, sharepoint_item_id, last_synced_at, last_error
FROM sharepoint_sync_state
ORDER BY last_synced_at DESC;
```

Common errors:

- **401**: tenant ID, client ID, or client secret is wrong or expired.
- **403**: admin consent is missing, or `Sites.Selected` was not granted to the target site.
- **404**: site ID or list ID is incorrect.
- **invalidRequest / field not recognized**: SharePoint internal column names do not match.

The local portal keeps working during these failures. Correct the configuration or permission and the worker will retry queued records.

## 9. Back up before deployment

Back up the active `mrs.db` and the current application folder before copying the changed files. On first start, the sync module adds its two tables and three triggers without deleting ticket data or changing the user interface.
