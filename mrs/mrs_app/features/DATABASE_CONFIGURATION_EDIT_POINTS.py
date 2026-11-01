"""
DATABASE CONFIGURATION COMMENTS - THESE ARE THE VALUES TO CHANGE
================================================================
JIRA: mrs_app/features/te_jira/routes.py
  DEFAULT_SERVER   = SQL Server and port
  DEFAULT_DATABASE = database name
  DEFAULT_VIEW     = [schema].[table_or_view]
  Search key SQL   = WHERE IssueId = ? inside _find_issue()

PIE: mrs_app/features/te_pie_tickets/routes.py
  DEFAULT_SERVER   = SQL Server or instance
  DEFAULT_DATABASE = database name
  DEFAULT_TABLE    = [schema].[table_name]
  Project search   = WHERE ... [PROJECTKEY] ... inside _find_project()
  Popup key SQL    = WHERE [id] = ? inside _find_ticket()

The environment-variable overrides are TE_JIRA_SQL_SERVER,
TE_JIRA_SQL_DATABASE, TE_JIRA_SQL_VIEW, TE_PIE_SQL_SERVER,
TE_PIE_SQL_DATABASE, and TE_PIE_SQL_TABLE.
"""
