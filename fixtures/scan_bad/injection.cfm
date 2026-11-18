<!--- ColdFusion injection samples (tag syntax plus a CFScript line).

 1. #uid# interpolated into a QueryExecute() SQL string.
 2. <cfset> assignment build: SQL assembled into a variable with #sid#.
 3. CFScript assignment build consumed on a later line.
 4. <cfexecute> tag with #path# interpolation inside the command attribute.
 5. CfExecute() with a &-concatenated command string.
 6. exec() (java.lang.Runtime style) fed a concatenated command string.
--->
<cfscript>
result = QueryExecute("SELECT * FROM orders WHERE uid = #uid#", {}, {datasource = "ds"});
</cfscript>

<cfset sql = "DELETE FROM sessions WHERE sid = #sid#">

<cfscript>
q = "UPDATE accounts SET balance = #balance#";
</cfscript>

<cfexecute name="cmd.exe" arguments="dir #folder#"></cfexecute>

<cfscript>
CfExecute("cmd.exe /c net user " & username);
</cfscript>

<cfscript>
runtime = CreateObject("java.lang.Runtime");
runtime.exec("cmd.exe /c ping -n 1 " & host);
</cfscript>
