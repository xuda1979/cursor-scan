<!--- Safe ColdFusion: all values bound via cfqueryparam / :name placeholders,
 and command strings are static literals. Expected: 0 findings. --->
<cfquery name="q" datasource="ds">
    SELECT * FROM users WHERE id = <cfqueryparam value="#form.id#" cfsqltype="cf_sql_integer">
</cfquery>

<cfset sql = "UPDATE accounts SET balance = :amt WHERE id = :id">

<cfscript>
result = QueryExecute("SELECT * FROM orders WHERE uid = :uid", {uid = uid});
params = {};
params.uid = url.uid;
QueryExecute("SELECT * FROM orders WHERE id = :uid", params);
</cfscript>

<cfexecute name="cmd.exe" arguments="/c cls"></cfexecute>

<cfscript>
CfExecute("cmd.exe /c cls");
</cfscript>
