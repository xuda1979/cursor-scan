-- Bad SQL: dynamic SQL built by string concatenation (EXECUTE IMMEDIATE /
-- EXEC / sp_executesql / CONCAT splice).  The `||` / `+` concatenation and
-- CONCAT() calls join a runtime value into a SQL statement.

-- PL/SQL: EXECUTE IMMEDIATE with `||` splice of a runtime variable.
CREATE OR REPLACE PROCEDURE get_user(p_id VARCHAR2) AS
BEGIN
    EXECUTE IMMEDIATE 'SELECT * FROM users WHERE id = ' || p_id;
    EXECUTE IMMEDIATE 'UPDATE accounts SET balance = balance + ' || p_amt
        || ' WHERE id = ' || p_id;
END;
/

-- T-SQL: EXEC with a `+`-concatenated statement.
DECLARE @sql NVARCHAR(MAX);
SET @sql = N'SELECT * FROM orders WHERE cust = ''' ;
EXEC(@sql + @cust_id + ')');
EXEC ( 'DELETE FROM sessions WHERE token = ' + @token );

-- SQL Server 2012+: CONCAT() is a SQL Server native concat function.
SET @sql = CONCAT('SELECT * FROM log WHERE app = ', @app);

-- MySQL stored procedure: PREPARE / EXECUTE with a CONCAT-built statement.
CREATE PROCEDURE find_item(IN fname VARCHAR(64))
BEGIN
    SET @s = CONCAT('SELECT * FROM items WHERE name = "', fname, '"');
    PREPARE stmt FROM @s;
    EXECUTE stmt USING @s;
    DEALLOCATE PREPARE stmt;
END//

-- sp_executesql with embedded `+` concat of a log message parameter.
DECLARE @logsql NVARCHAR(200);
SET @logsql = N'INSERT INTO audit (msg) VALUES (N''' + @msg + N''')';
EXEC sp_executesql @logsql;
