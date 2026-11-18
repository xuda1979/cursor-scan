-- Good SQL: parameterized / bound dynamic SQL, static literals.
-- Bind-variable and parameterized forms keep user input out of the
-- statement text, so none of these should be flagged.

-- PL/SQL: EXECUTE IMMEDIATE ... USING binds values separately.
CREATE OR REPLACE PROCEDURE get_user(p_id NUMBER) AS
BEGIN
    EXECUTE IMMEDIATE 'SELECT * FROM users WHERE id = :id' USING p_id;
    EXECUTE IMMEDIATE 'UPDATE accounts SET balance = balance + :amt WHERE id = :id'
        USING p_amt, p_id;
END;
/

-- T-SQL: sp_executesql with a parameter list (bound, not concatenated).
DECLARE @sql NVARCHAR(MAX) = N'SELECT * FROM orders WHERE cust = @cust';
DECLARE @params NVARCHAR(MAX) = N'@cust INT';
EXEC sp_executesql @sql, @params, @cust = @cust_id;

-- Static literals: no runtime value enters the statement.
SELECT * FROM orders WHERE status = 'SHIPPED';
UPDATE accounts SET balance = 0 WHERE id = 1;

-- MySQL PREPARE with placeholder ? and bound EXECUTE ... USING.
SET @s = 'SELECT * FROM items WHERE name = ?';
PREPARE stmt FROM @s;
EXECUTE stmt USING @name;
DEALLOCATE PREPARE stmt;

-- A `||` used for display text outside a statement is harmless prose.
SELECT 'Report for ' || TO_CHAR(CURRENT_DATE) AS header FROM dual;
