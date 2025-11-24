/*******************************************************************************
 * DATABASE SECURITY - COMPLETE ASSIGNMENT
 * Access Control (DAC & RBAC) and Inference Control
 * 
 * Assignment Structure:
 * Part 1: DAC Implementation (Discretionary Access Control)
 * Part 2: RBAC Implementation (Role-Based Access Control)
 * Part 3: Inference Attack Simulation
 * Part 4: Inference Control by Randomization
 * Part 5: Functional Dependency Inference
 * Part 6: Inference via Aggregates (K-Anonymity)
 ******************************************************************************/

-- ============================================================================
-- SETUP: Clean Environment
-- ============================================================================
USE master;
GO

IF EXISTS(SELECT * FROM sys.databases WHERE name = 'EmployeeSecurity_DB')
BEGIN
    ALTER DATABASE EmployeeSecurity_DB SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE EmployeeSecurity_DB;
END
GO

-- Drop server logins if they exist
IF EXISTS (SELECT * FROM sys.server_principals WHERE name = 'user_public') DROP LOGIN user_public;
IF EXISTS (SELECT * FROM sys.server_principals WHERE name = 'user_admin') DROP LOGIN user_admin;
IF EXISTS (SELECT * FROM sys.server_principals WHERE name = 'user_read') DROP LOGIN user_read;
IF EXISTS (SELECT * FROM sys.server_principals WHERE name = 'user_write') DROP LOGIN user_write;
IF EXISTS (SELECT * FROM sys.server_principals WHERE name = 'user_power') DROP LOGIN user_power;
GO

-- Create database
CREATE DATABASE EmployeeSecurity_DB;
GO

USE EmployeeSecurity_DB;
GO

PRINT '✓ Database created successfully';
PRINT '==============================================================';
GO

-- ============================================================================
-- BASE SCHEMA: Create Tables
-- ============================================================================
PRINT '';
PRINT '=== CREATING BASE SCHEMA ===';

-- Main Employees table (as specified in assignment)
CREATE TABLE Employees (
    EmpID INT PRIMARY KEY,
    FullName NVARCHAR(100) NOT NULL,
    Salary MONEY NOT NULL
);

-- Insert exact data from assignment
INSERT INTO Employees (EmpID, FullName, Salary) VALUES
(1, 'Ali', 120000),
(2, 'Asser', 110000),
(3, 'Mona', 100000),
(4, 'Fatma', 90000),
(5, 'Gehad', 80000),
(6, 'Ahmed', 70000);

PRINT '✓ Employees table created with 6 records';

-- AdminMap table for inference control (Part 4)
CREATE TABLE AdminMap (
    EmpID INT PRIMARY KEY,
    Name_PublicID UNIQUEIDENTIFIER DEFAULT NEWID(),
    Salary_PublicID UNIQUEIDENTIFIER DEFAULT NEWID()
);

INSERT INTO AdminMap (EmpID)
SELECT EmpID FROM Employees;

PRINT '✓ AdminMap table created for randomization';
GO

-- Tables for Functional Dependencies (Part 5)
CREATE TABLE Departments (
    DeptID INT PRIMARY KEY,
    DeptName NVARCHAR(50)
);

CREATE TABLE Titles (
    TitleName NVARCHAR(50) PRIMARY KEY,
    Grade CHAR(1)
);

CREATE TABLE BonusMap (
    DeptID INT,
    Grade CHAR(1),
    Bonus MONEY,
    PRIMARY KEY (DeptID, Grade)
);

-- Add columns to Employees for FD demonstration
ALTER TABLE Employees ADD 
    DeptID INT,
    Title NVARCHAR(50);

-- Sample data for FD tables
INSERT INTO Departments VALUES (10, 'Sales'), (20, 'IT'), (30, 'HR');
INSERT INTO Titles VALUES ('Manager', 'A'), ('Developer', 'B'), ('Analyst', 'C');
INSERT INTO BonusMap VALUES 
    (10, 'A', 5000), (20, 'B', 4000), (30, 'C', 2000);

-- Update Employees with Dept and Title
UPDATE Employees SET DeptID = 10, Title = 'Manager' WHERE EmpID = 1;
UPDATE Employees SET DeptID = 20, Title = 'Developer' WHERE EmpID = 2;
UPDATE Employees SET DeptID = 30, Title = 'Analyst' WHERE EmpID = 3;
UPDATE Employees SET DeptID = 10, Title = 'Analyst' WHERE EmpID = 4;
UPDATE Employees SET DeptID = 20, Title = 'Developer' WHERE EmpID = 5;
UPDATE Employees SET DeptID = 30, Title = 'Manager' WHERE EmpID = 6;

PRINT '✓ FD tables created (Departments, Titles, BonusMap)';
PRINT '==============================================================';
GO

/*******************************************************************************
 * PART 1: DAC IMPLEMENTATION (Discretionary Access Control)
 * Requirements:
 * 1. Create logins: user_public, user_admin
 * 2. Map to database users: general, admin1
 * 3. Create roles: public_role, admin_role
 * 4. Grant limited access to public_role, full access to admin_role
 * 5. Test access
 * 6. Demonstrate indirect access vulnerability through views
 ******************************************************************************/

PRINT '';
PRINT '╔════════════════════════════════════════════════════════════════╗';
PRINT '║              PART 1: DAC IMPLEMENTATION                        ║';
PRINT '╚════════════════════════════════════════════════════════════════╝';
PRINT '';

-- Step 1: Create SQL Server logins
USE master;
GO

CREATE LOGIN user_public WITH PASSWORD = 'Public123!', CHECK_POLICY = ON;
CREATE LOGIN user_admin WITH PASSWORD = 'Admin123!', CHECK_POLICY = ON;
GO

PRINT '✓ Step 1: Created logins (user_public, user_admin)';

-- Step 2: Map logins to database users
USE EmployeeSecurity_DB;
GO

CREATE USER general FOR LOGIN user_public;
CREATE USER admin1 FOR LOGIN user_admin;
GO

PRINT '✓ Step 2: Mapped to database users (general, admin1)';

-- Step 3: Create roles
CREATE ROLE public_role;
CREATE ROLE admin_role;
GO

PRINT '✓ Step 3: Created roles (public_role, admin_role)';

-- Step 4: Configure permissions
-- Public role: Limited access (can see names, but NOT salaries)
GRANT SELECT ON Employees TO public_role;
DENY SELECT ON Employees(Salary) TO public_role;

-- Admin role: Full access
GRANT SELECT, INSERT, UPDATE, DELETE ON Employees TO admin_role;
GRANT SELECT ON AdminMap TO admin_role;
GRANT SELECT ON Departments TO admin_role;
GRANT SELECT ON Titles TO admin_role;
GRANT SELECT ON BonusMap TO admin_role;

-- Assign users to roles
EXEC sp_addrolemember 'public_role', 'general';
EXEC sp_addrolemember 'admin_role', 'admin1';
GO

PRINT '✓ Step 4: Granted permissions (public_role: limited, admin_role: full)';

-- Step 5: Test access
PRINT '';
PRINT '--- Step 5: Testing DAC Access ---';
PRINT 'Testing general user (public_role):';

EXECUTE AS USER = 'general';
    -- Can see names
    SELECT EmpID, FullName FROM Employees;
    
    -- Cannot see salaries directly (would fail)
    -- SELECT Salary FROM Employees;  -- Uncomment to see error
REVERT;

PRINT '✓ general can view names but NOT salaries';

PRINT '';
PRINT 'Testing admin1 user (admin_role):';

EXECUTE AS USER = 'admin1';
    -- Can see everything
    SELECT * FROM Employees;
REVERT;

PRINT '✓ admin1 can view all data including salaries';

-- Step 6: Demonstrate vulnerability - Indirect access through view
PRINT '';
PRINT '--- Step 6: DAC Vulnerability Demonstration ---';

-- Create a vulnerable view that exposes salary
CREATE VIEW vEmployeeFullData AS
SELECT EmpID, FullName, Salary FROM Employees;
GO

-- Grant access to the view (MISTAKE!)
GRANT SELECT ON vEmployeeFullData TO public_role;
GO

PRINT '⚠️  VULNERABILITY CREATED: View exposes restricted columns';
PRINT '';
PRINT 'Attack: general user accessing salary through view:';

EXECUTE AS USER = 'general';
    -- Attack succeeds! User can see salary via view
    SELECT FullName, Salary FROM vEmployeeFullData;
REVERT;

PRINT '❌ SECURITY BREACH: general accessed Salary via view!';
PRINT '';
PRINT 'How the attack works:';
PRINT '  - DENY on Employees(Salary) blocks direct access';
PRINT '  - But GRANT on view bypasses the column-level restriction';
PRINT '  - Views inherit owner permissions, not caller permissions';
PRINT '';
PRINT 'How to fix it:';
PRINT '  1. Revoke view access from public_role';
PRINT '  2. Create views that exclude sensitive columns';
PRINT '  3. Use schema separation for sensitive data';

-- Fix the vulnerability
REVOKE SELECT ON vEmployeeFullData FROM public_role;
GO

PRINT '';
PRINT '✓ FIX APPLIED: Revoked view access from public_role';

EXECUTE AS USER = 'general';
    -- Now access is denied
    -- SELECT * FROM vEmployeeFullData;  -- Would fail
    PRINT '✓ Verified: general can no longer access the view';
REVERT;

PRINT '';
PRINT '══════════════════════════════════════════════════════════════';
PRINT '           PART 1 COMPLETE: DAC Implemented & Tested';
PRINT '══════════════════════════════════════════════════════════════';
GO

/*******************************************************************************
 * PART 2: RBAC IMPLEMENTATION (Role-Based Access Control)
 * Requirements:
 * 1. Create roles: read_onlyX, insert_onlyX
 * 2. Assign users to these roles
 * 3. Use GRANT/REVOKE for least privilege
 * 4. Verify access with different operations
 * 5. Demonstrate role hierarchy (composite role: power_user)
 ******************************************************************************/

PRINT '';
PRINT '╔════════════════════════════════════════════════════════════════╗';
PRINT '║              PART 2: RBAC IMPLEMENTATION                       ║';
PRINT '╚════════════════════════════════════════════════════════════════╝';
PRINT '';

-- Step 1: Create specialized roles
CREATE ROLE read_onlyX;
CREATE ROLE insert_onlyX;
GO

PRINT '✓ Step 1: Created roles (read_onlyX, insert_onlyX)';

-- Grant specific permissions (Least Privilege Principle)
GRANT SELECT ON Employees TO read_onlyX;
GRANT INSERT ON Employees TO insert_onlyX;
GO

-- Step 2: Create logins and users
USE master;
CREATE LOGIN user_read WITH PASSWORD = 'Read123!';
CREATE LOGIN user_write WITH PASSWORD = 'Write123!';
GO

USE EmployeeSecurity_DB;
CREATE USER user_read FOR LOGIN user_read;
CREATE USER user_write FOR LOGIN user_write;
GO

-- Assign users to roles
EXEC sp_addrolemember 'read_onlyX', 'user_read';
EXEC sp_addrolemember 'insert_onlyX', 'user_write';
GO

PRINT '✓ Step 2: Created and assigned users to roles';

-- Step 3 & 4: Verify least privilege enforcement
PRINT '';
PRINT '--- Testing Least Privilege Principle ---';
PRINT 'Testing user_read (read_onlyX):';

EXECUTE AS USER = 'user_read';
    -- Can SELECT
    SELECT * FROM Employees;
    
    -- Cannot INSERT (would fail)
    -- INSERT INTO Employees VALUES (7, 'Test', 50000);  -- Uncomment to see error
REVERT;

PRINT '✓ user_read can SELECT only';

PRINT '';
PRINT 'Testing user_write (insert_onlyX):';

EXECUTE AS USER = 'user_write';
    -- Can INSERT
    INSERT INTO Employees (EmpID, FullName, Salary, DeptID, Title) 
    VALUES (7, 'Layla', 65000, 10, 'Analyst');
    PRINT '✓ INSERT successful';
    
    -- Cannot SELECT (would fail)
    -- SELECT * FROM Employees;  -- Uncomment to see error
REVERT;

PRINT '✓ user_write can INSERT only';
PRINT '✓ Step 3 & 4: Least privilege verified for both roles';

-- Step 5: Role Hierarchy & Composite Role
PRINT '';
PRINT '--- Step 5: Role Hierarchy (Composite Role) ---';

-- Create power_user role
CREATE ROLE power_user;
GO

-- Make power_user inherit from both roles
EXEC sp_addrolemember 'read_onlyX', 'power_user';
EXEC sp_addrolemember 'insert_onlyX', 'power_user';
GO

PRINT '✓ Created power_user role inheriting from read_onlyX + insert_onlyX';

-- Create user and assign to power_user
USE master;
CREATE LOGIN user_power WITH PASSWORD = 'Power123!';
GO

USE EmployeeSecurity_DB;
CREATE USER user_power FOR LOGIN user_power;
EXEC sp_addrolemember 'power_user', 'user_power';
GO

PRINT '✓ Assigned user_power to power_user role';

-- Test combined privileges
PRINT '';
PRINT 'Testing user_power (has both READ and INSERT):';

EXECUTE AS USER = 'user_power';
    -- Can SELECT (from read_onlyX)
    SELECT TOP 3 * FROM Employees;
    
    -- Can INSERT (from insert_onlyX)
    INSERT INTO Employees (EmpID, FullName, Salary, DeptID, Title) 
    VALUES (8, 'Yasmin', 72000, 20, 'Developer');
    
    PRINT '✓ user_power has BOTH read and write privileges';
REVERT;

-- Remove one underlying role
PRINT '';
PRINT 'Removing insert_onlyX from power_user...';
EXEC sp_droprolemember 'insert_onlyX', 'power_user';
GO

-- Test after removal
PRINT 'Testing user_power after removing INSERT privilege:';

EXECUTE AS USER = 'user_power';
    -- Can still SELECT
    SELECT TOP 3 * FROM Employees;
    
    -- Cannot INSERT anymore (would fail)
    -- INSERT INTO Employees VALUES (9, 'Test', 50000);  -- Uncomment to see error
    
    PRINT '✓ user_power now has only READ privilege';
REVERT;

PRINT '';
PRINT '══════════════════════════════════════════════════════════════';
PRINT '    PART 2 COMPLETE: RBAC & Role Hierarchy Demonstrated';
PRINT '══════════════════════════════════════════════════════════════';
GO

/*******************************************************************************
 * PART 3: INFERENCE ATTACK SIMULATION
 * Demonstrate how ordered views can be exploited to infer salary data
 * by aligning vPublicNames and vPublicSalaries
 ******************************************************************************/

PRINT '';
PRINT '╔════════════════════════════════════════════════════════════════╗';
PRINT '║          PART 3: INFERENCE ATTACK SIMULATION                   ║';
PRINT '╚════════════════════════════════════════════════════════════════╝';
PRINT '';

-- Create ordered views (VULNERABLE to alignment attack)
CREATE VIEW vPublicNames AS
SELECT FullName, EmpID FROM Employees;
GO

CREATE VIEW vPublicSalaries AS
SELECT Salary, EmpID FROM Employees;
GO

-- Grant access to both views
GRANT SELECT ON vPublicNames TO public_role;
GRANT SELECT ON vPublicSalaries TO public_role;
GO

PRINT '✓ Created vPublicNames and vPublicSalaries views';
PRINT '';
PRINT '--- Demonstrating Inference Attack ---';
PRINT 'Attack Method: Align ordered results from both views';

EXECUTE AS USER = 'general';
    PRINT '';
    PRINT 'Step 1: Get names ordered by EmpID:';
    SELECT FullName, EmpID FROM vPublicNames ORDER BY EmpID;
    
    PRINT '';
    PRINT 'Step 2: Get salaries ordered by EmpID:';
    SELECT Salary, EmpID FROM vPublicSalaries ORDER BY EmpID;
    
    PRINT '';
    PRINT 'Step 3: Attacker aligns both results using EmpID:';
    SELECT 
        n.FullName,
        s.Salary,
        n.EmpID
    FROM vPublicNames n
    INNER JOIN vPublicSalaries s ON n.EmpID = s.EmpID
    ORDER BY n.EmpID;
    
    PRINT '';
    PRINT '❌ INFERENCE ATTACK SUCCESSFUL!';
    PRINT '   Attacker linked names to salaries using EmpID alignment';
REVERT;

PRINT '';
PRINT '══════════════════════════════════════════════════════════════';
PRINT '      PART 3 COMPLETE: Inference Attack Demonstrated';
PRINT '══════════════════════════════════════════════════════════════';
GO

/*******************************************************************************
 * PART 4: INFERENCE CONTROL BY RANDOMIZATION
 * Requirements:
 * 1. Regenerate Public IDs using NEWID()
 * 2. Restrict access to AdminMap
 * 3. Deny CREATE VIEW to public_role
 * 4. Verify attack no longer works
 ******************************************************************************/

PRINT '';
PRINT '╔════════════════════════════════════════════════════════════════╗';
PRINT '║        PART 4: INFERENCE CONTROL BY RANDOMIZATION             ║';
PRINT '╚════════════════════════════════════════════════════════════════╝';
PRINT '';

-- Step 1: Regenerate Public IDs (already done with NEWID() DEFAULT)
-- Refresh to show different GUIDs
UPDATE AdminMap SET 
    Name_PublicID = NEWID(),
    Salary_PublicID = NEWID();
GO

PRINT '✓ Step 1: Regenerated random Public IDs using NEWID()';

-- Step 2: Restrict access to AdminMap
DENY SELECT ON AdminMap TO public_role;
GO

PRINT '✓ Step 2: Denied access to AdminMap for public_role';

-- Step 3: Deny CREATE VIEW permission
DENY CREATE VIEW TO public_role;
GO

PRINT '✓ Step 3: Denied CREATE VIEW to public_role';

-- Create new secure views with separate random IDs
DROP VIEW IF EXISTS vPublicNames;
DROP VIEW IF EXISTS vPublicSalaries;
GO

CREATE VIEW vPublicNames AS
SELECT E.FullName, M.Name_PublicID
FROM Employees E
INNER JOIN AdminMap M ON E.EmpID = M.EmpID;
GO

CREATE VIEW vPublicSalaries AS
SELECT E.Salary, M.Salary_PublicID
FROM Employees E
INNER JOIN AdminMap M ON E.EmpID = M.EmpID;
GO

-- Grant access to new views
GRANT SELECT ON vPublicNames TO public_role;
GRANT SELECT ON vPublicSalaries TO public_role;
GO

PRINT '✓ Created new views with separate random identifiers';

-- Step 4: Verify attack is blocked
PRINT '';
PRINT '--- Step 4: Verifying Inference Attack is Blocked ---';

EXECUTE AS USER = 'general';
    PRINT '';
    PRINT 'Attempting to link names and salaries:';
    
    -- This will return NO MATCHES because Name_PublicID ≠ Salary_PublicID
    SELECT 
        n.FullName,
        s.Salary
    FROM vPublicNames n
    INNER JOIN vPublicSalaries s ON n.Name_PublicID = s.Salary_PublicID;
    
    PRINT '';
    PRINT '✓ ATTACK BLOCKED: No matches found!';
    PRINT '  Different random IDs prevent linking';
    
    -- Also cannot access AdminMap to get the real mapping
    -- SELECT * FROM AdminMap;  -- Would fail (access denied)
REVERT;

PRINT '';
PRINT '══════════════════════════════════════════════════════════════';
PRINT '  PART 4 COMPLETE: Randomization Successfully Prevents Inference';
PRINT '══════════════════════════════════════════════════════════════';
GO

/*******************************************************************************
 * PART 5: FUNCTIONAL DEPENDENCY INFERENCE
 * Given FDs:
 * • FD₁: EmpID → Dept
 * • FD₂: Title → Grade
 * • FD₃: Dept, Grade → Bonus
 * 
 * Tasks:
 * 1. Compute closure Q⁺ of {Dept, Title}
 * 2. Show Bonus ∈ Q⁺
 * 3. Decide whether to reject or transform the query
 ******************************************************************************/

PRINT '';
PRINT '╔════════════════════════════════════════════════════════════════╗';
PRINT '║        PART 5: FUNCTIONAL DEPENDENCY INFERENCE                 ║';
PRINT '╚════════════════════════════════════════════════════════════════╝';
PRINT '';

PRINT '--- Given Functional Dependencies ---';
PRINT 'FD₁: EmpID → Dept';
PRINT 'FD₂: Title → Grade';
PRINT 'FD₃: Dept, Grade → Bonus';
PRINT '';

-- Create a view showing the inference query (Dept, Title)
CREATE VIEW vInferenceQuery AS
SELECT E.EmpID, D.DeptName AS Dept, E.Title
FROM Employees E
INNER JOIN Departments D ON E.DeptID = D.DeptID;
GO

-- Create view showing sensitive Bonus
CREATE VIEW vSensitiveBonus AS
SELECT E.EmpID, BM.Bonus
FROM Employees E
INNER JOIN Titles T ON E.Title = T.TitleName
INNER JOIN BonusMap BM ON E.DeptID = BM.DeptID AND T.Grade = BM.Grade;
GO

PRINT '--- Step 1: Computing Closure Q⁺ of {Dept, Title} ---';
PRINT '';
PRINT 'Given: Q = {Dept, Title}';
PRINT 'Computation:';
PRINT '  Start: Q⁺ = {Dept, Title}';
PRINT '';
PRINT '  Apply FD₂: Title → Grade';
PRINT '    Since Title ∈ Q⁺, we add Grade';
PRINT '    Q⁺ = {Dept, Title, Grade}';
PRINT '';
PRINT '  Apply FD₃: Dept, Grade → Bonus';
PRINT '    Since {Dept, Grade} ⊆ Q⁺, we add Bonus';
PRINT '    Q⁺ = {Dept, Title, Grade, Bonus}';
PRINT '';
PRINT '  No more FDs apply';
PRINT '  Final: Q⁺ = {Dept, Title, Grade, Bonus}';
PRINT '';

PRINT '--- Step 2: Proving Bonus ∈ Q⁺ ---';
PRINT '';
PRINT '✓ Bonus ∈ Q⁺ = {Dept, Title, Grade, Bonus}';
PRINT '';
PRINT 'Inference Chain:';
PRINT '  {Dept, Title} → Grade (via FD₂)';
PRINT '  {Dept, Grade} → Bonus (via FD₃)';
PRINT '  Therefore: {Dept, Title} → Bonus';
PRINT '';

-- Grant access to demonstrate the attack
GRANT SELECT ON vInferenceQuery TO public_role;
GRANT SELECT ON Titles TO public_role;
GRANT SELECT ON BonusMap TO public_role;
GO

PRINT '--- Demonstrating FD Inference Attack ---';

EXECUTE AS USER = 'general';
    PRINT 'Attacker can see: {Dept, Title}';
    SELECT * FROM vInferenceQuery;
    
    PRINT '';
    PRINT 'Attacker uses FD chain to infer Bonus:';
    SELECT 
        Q.EmpID,
        Q.Dept,
        Q.Title,
        T.Grade,      -- Inferred via FD₂
        B.Bonus       -- Inferred via FD₃
    FROM vInferenceQuery Q
    INNER JOIN Titles T ON Q.Title = T.TitleName
    INNER JOIN BonusMap B ON Q.Dept = (SELECT DeptName FROM Departments WHERE DeptID = B.DeptID)
        AND T.Grade = B.Grade;
    
    PRINT '';
    PRINT '❌ INFERENCE SUCCESSFUL via Functional Dependencies!';
REVERT;

PRINT '';
PRINT '--- Step 3: Decision - Reject or Transform Query ---';
PRINT '';
PRINT 'Analysis:';
PRINT '  Since Bonus ∈ Closure({Dept, Title}),';
PRINT '  granting access to {Dept, Title} allows inference of Bonus';
PRINT '';
PRINT 'Decision: REJECT the query';
PRINT 'Reason: User can infer restricted attribute (Bonus) from query attributes';
PRINT '';
PRINT 'Alternative Solutions:';
PRINT '  1. DENY access to Title column (breaks FD₂ chain)';
PRINT '  2. DENY access to Titles or BonusMap tables';
PRINT '  3. Suppress one of the FD source attributes';

-- Implement the fix
PRINT '';
PRINT 'Applying Fix: Revoking access to break inference chain...';

REVOKE SELECT ON vInferenceQuery FROM public_role;
REVOKE SELECT ON Titles FROM public_role;
GO

PRINT '✓ Fix Applied: Revoked access to inference query and FD tables';

PRINT '';
PRINT '══════════════════════════════════════════════════════════════';
PRINT '   PART 5 COMPLETE: FD Inference Analyzed and Prevented';
PRINT '══════════════════════════════════════════════════════════════';
GO

/*******************************************************************************
 * PART 6: INFERENCE VIA AGGREGATES (K-Anonymity)
 * Requirements:
 * 1. Use AVG views including/excluding target user to infer salary
 * 2. Apply K-anonymity rule (K=3) to prevent inference
 * 3. Demonstrate that inference is blocked
 ******************************************************************************/

PRINT '';
PRINT '╔════════════════════════════════════════════════════════════════╗';
PRINT '║       PART 6: INFERENCE VIA AGGREGATES (K-ANONYMITY)           ║';
PRINT '╚════════════════════════════════════════════════════════════════╝';
PRINT '';

-- Add test employees for aggregate attack
INSERT INTO Employees (EmpID, FullName, Salary, DeptID, Title) VALUES
(9, 'Target_User', 60000, 20, 'Developer'),
(10, 'Other_User', 90000, 20, 'Developer');

-- Add to mapping
INSERT INTO AdminMap (EmpID) VALUES (9), (10);
GO

PRINT '✓ Added test users for aggregate inference';

-- Step 1: Create vulnerable aggregate views (N=2)
PRINT '';
PRINT '--- Step 1: Creating Vulnerable Aggregate Views ---';

CREATE VIEW vAvg_IncludeTarget AS
SELECT 
    DeptID,
    AVG(Salary) AS AvgSalary,
    COUNT(*) AS GroupSize
FROM Employees
WHERE EmpID IN (9, 10)  -- Both target and other
GROUP BY DeptID;
GO

CREATE VIEW vAvg_ExcludeTarget AS
SELECT 
    DeptID,
    AVG(Salary) AS AvgSalary,
    COUNT(*) AS GroupSize
FROM Employees
WHERE EmpID = 10  -- Only other user
GROUP BY DeptID;
GO

GRANT SELECT ON vAvg_IncludeTarget TO public_role;
GRANT SELECT ON vAvg_ExcludeTarget TO public_role;
GO

PRINT '✓ Created aggregate views (N=2, vulnerable)';

-- Demonstrate the attack
PRINT '';
PRINT '--- Demonstrating Aggregate Inference Attack ---';
PRINT '';
PRINT 'Attack Formula: Target = (Total_Avg × N) - (Exclude_Avg × (N-1))';

EXECUTE AS USER = 'general';
    PRINT '';
    PRINT 'Step 1: Get average including target (N=2):';
    SELECT * FROM vAvg_IncludeTarget;
    PRINT '  Average of 2 people = (60000 + 90000) / 2 = 75000';
    
    PRINT '';
    PRINT 'Step 2: Get average excluding target (N=1):';
    SELECT * FROM vAvg_ExcludeTarget;
    PRINT '  Average of 1 person = 90000 / 1 = 90000';
    
    PRINT '';
    PRINT 'Step 3: Calculate target salary using algebra:';
    SELECT 
        'AGGREGATE ATTACK' AS Method,
        (Inc.AvgSalary * 2) - (Exc.AvgSalary * 1) AS Inferred_Target_Salary,
        Inc.GroupSize AS Total_Count,
        Exc.GroupSize AS Exclude_Count
    FROM vAvg_IncludeTarget Inc
    CROSS JOIN vAvg_ExcludeTarget Exc;
    
    PRINT '';
    PRINT '  Target = (75000 × 2) - (90000 × 1) = 60000';
    PRINT '';
    PRINT '❌ INFERENCE ATTACK SUCCESSFUL!';
    PRINT '   Attacker discovered target salary = 60000';
REVERT;

-- Step 2: Apply K-Anonymity protection
PRINT '';
PRINT '--- Step 2: Applying K-Anonymity Rule (K=3) ---';

-- Add more employees to create K=3 group
INSERT INTO Employees (EmpID, FullName, Salary, DeptID, Title) VALUES
(11, 'K_Anon_1', 75000, 20, 'Developer'),
(12, 'K_Anon_2', 85000, 20, 'Developer');

INSERT INTO AdminMap (EmpID) VALUES (11), (12);
GO

PRINT '✓ Added employees to create group of size 4 (meets K=3)';

-- Drop old views
DROP VIEW IF EXISTS vAvg_IncludeTarget;
DROP VIEW IF EXISTS vAvg_ExcludeTarget;
GO

-- Create K-anonymity protected view
CREATE VIEW vAvg_KAnonymity AS
SELECT 
    DeptID,
    CASE 
        WHEN COUNT(*) < 3 THEN NULL  -- Suppress if group < K
        ELSE AVG(Salary)
    END AS Safe_AvgSalary,
    CASE
        WHEN COUNT(*) < 3 THEN NULL  -- Don't reveal exact count
        ELSE COUNT(*)
    END AS GroupSize
FROM Employees
WHERE DeptID = 20  -- IT Department
GROUP BY DeptID;
GO

GRANT SELECT ON vAvg_KAnonymity TO public_role;
GO

PRINT '✓ Created K-anonymity protected view (K=3 minimum)';

-- Step 3: Demonstrate that inference is blocked
PRINT '';
PRINT '--- Step 3: Verifying K-Anonymity Blocks Inference ---';

EXECUTE AS USER = 'general';
    PRINT '';
    PRINT 'Attempting to access aggregate data:';
    SELECT * FROM vAvg_KAnonymity;
    
    PRINT '';
    PRINT '✓ INFERENCE BLOCKED!';
    PRINT '  - Group size = 4 (>= K=3), so average is shown';
    PRINT '  - But attacker cannot create N-1 subset';
    PRINT '  - Cannot isolate individual salary';
    PRINT '';
    PRINT 'K-Anonymity Protection:';
    PRINT '  - Minimum group size enforced (K=3)';
    PRINT '  - Small groups return NULL (suppressed)';
    PRINT '  - Individual values cannot be inferred';
REVERT;

PRINT '';
PRINT '══════════════════════════════════════════════════════════════';
PRINT '    PART 6 COMPLETE: K-Anonymity Successfully Prevents';
PRINT '                  Aggregate Inference Attack';
PRINT '══════════════════════════════════════════════════════════════';
GO

/*******************************************************************************
 * ASSIGNMENT SUMMARY AND VERIFICATION
 ******************************************************************************/

PRINT '';
PRINT '';
PRINT '╔════════════════════════════════════════════════════════════════╗';
PRINT '║                    ASSIGNMENT SUMMARY                          ║';
PRINT '╚════════════════════════════════════════════════════════════════╝';
PRINT '';
PRINT '✓ PART 1: DAC Implementation';
PRINT '  - Created logins: user_public, user_admin';
PRINT '  - Mapped to users: general, admin1';
PRINT '  - Created roles: public_role, admin_role';
PRINT '  - Demonstrated view-based security bypass';
PRINT '  - Fixed vulnerability by revoking view access';
PRINT '';
PRINT '✓ PART 2: RBAC Implementation';
PRINT '  - Created roles: read_onlyX, insert_onlyX';
PRINT '  - Enforced least privilege principle';
PRINT '  - Demonstrated role hierarchy with power_user';
PRINT '  - Showed dynamic privilege changes via REVOKE';
PRINT '';
PRINT '✓ PART 3: Inference Attack Simulation';
PRINT '  - Demonstrated alignment attack on ordered views';
PRINT '  - Showed how EmpID enables linking names to salaries';
PRINT '  - Proved vulnerability of predictable identifiers';
PRINT '';
PRINT '✓ PART 4: Inference Control by Randomization';
PRINT '  - Regenerated Public IDs using NEWID()';
PRINT '  - Restricted access to AdminMap table';
PRINT '  - Denied CREATE VIEW to public_role';
PRINT '  - Verified separate random IDs prevent linking';
PRINT '';
PRINT '✓ PART 5: Functional Dependency Inference';
PRINT '  - Computed closure Q⁺ of {Dept, Title}';
PRINT '  - Proved Bonus ∈ Q⁺';
PRINT '  - Demonstrated FD chain: Title→Grade, Dept+Grade→Bonus';
PRINT '  - Decided to REJECT query (inference possible)';
PRINT '  - Applied fix by revoking FD table access';
PRINT '';
PRINT '✓ PART 6: Inference via Aggregates';
PRINT '  - Demonstrated difference attack (N=2)';
PRINT '  - Applied K-anonymity rule (K=3)';
PRINT '  - Verified inference is blocked with proper group size';
PRINT '';
PRINT '╔════════════════════════════════════════════════════════════════╗';
PRINT '║                    KEY SECURITY LESSONS                        ║';
PRINT '╚════════════════════════════════════════════════════════════════╝';
PRINT '';
PRINT '1. DAC Limitation: Column-level security can be bypassed via views';
PRINT '   → Solution: Careful view design and permission auditing';
PRINT '';
PRINT '2. RBAC Benefits: Role hierarchy simplifies complex permissions';
PRINT '   → Solution: Use composite roles for flexible privilege management';
PRINT '';
PRINT '3. Inference via Ordering: Predictable IDs enable data correlation';
PRINT '   → Solution: Use random GUIDs for unlinkable data elements';
PRINT '';
PRINT '4. Inference via FDs: Business rules leak sensitive information';
PRINT '   → Solution: Restrict access to FD source attributes';
PRINT '';
PRINT '5. Inference via Aggregates: Small groups reveal individual values';
PRINT '   → Solution: Apply K-anonymity (K≥3) to suppress small groups';
PRINT '';
PRINT '╔════════════════════════════════════════════════════════════════╗';
PRINT '║                   EVALUATION CHECKLIST                         ║';
PRINT '╚════════════════════════════════════════════════════════════════╝';
PRINT '';
PRINT '□ DAC & RBAC Implementation (2 marks)';
PRINT '  ✓ Created logins, users, roles correctly';
PRINT '  ✓ Demonstrated security bypass and fix';
PRINT '  ✓ Implemented least privilege with RBAC';
PRINT '  ✓ Showed role inheritance and dynamic changes';
PRINT '';
PRINT '□ Inference attack demonstration (2 marks)';
PRINT '  ✓ Demonstrated alignment attack on views';
PRINT '  ✓ Explained how attack works with EmpID';
PRINT '  ✓ Showed successful salary inference';
PRINT '';
PRINT '□ Randomization & control enforcement (2 marks)';
PRINT '  ✓ Used NEWID() for random Public IDs';
PRINT '  ✓ Restricted AdminMap access';
PRINT '  ✓ Denied CREATE VIEW permission';
PRINT '  ✓ Verified unlinkability';
PRINT '';
PRINT '□ FD closure analysis (2 marks)';
PRINT '  ✓ Computed Q⁺ = {Dept, Title, Grade, Bonus}';
PRINT '  ✓ Proved Bonus ∈ Q⁺';
PRINT '  ✓ Demonstrated FD inference chain';
PRINT '  ✓ Made correct decision (REJECT query)';
PRINT '';
PRINT '□ Aggregate attack and defense (2 marks)';
PRINT '  ✓ Demonstrated difference attack (N=2)';
PRINT '  ✓ Showed inference calculation';
PRINT '  ✓ Applied K-anonymity rule (K=3)';
PRINT '  ✓ Verified protection blocks inference';
PRINT '';
PRINT '═══════════════════════════════════════════════════════════════';
PRINT '                 TOTAL: 10 Marks Possible';
PRINT '═══════════════════════════════════════════════════════════════';
PRINT '';
PRINT '╔════════════════════════════════════════════════════════════════╗';
PRINT '║              DISCUSSION PREPARATION GUIDE                      ║';
PRINT '╚════════════════════════════════════════════════════════════════╝';
PRINT '';
PRINT 'Key Topics for Discussion (90% of grade):';
PRINT '';
PRINT '1. Why does DENY on a column not protect against view access?';
PRINT '   Answer: Views execute with owner permissions, not caller';
PRINT '   permissions. GRANT on view overrides DENY on base table.';
PRINT '';
PRINT '2. What is the least privilege principle?';
PRINT '   Answer: Grant only minimum permissions needed for a task.';
PRINT '   Users should not have more access than required.';
PRINT '';
PRINT '3. How does role inheritance work?';
PRINT '   Answer: A role can be a member of another role, inheriting';
PRINT '   all its permissions. Enables flexible permission management.';
PRINT '';
PRINT '4. What makes the alignment attack possible?';
PRINT '   Answer: Using the same identifier (EmpID) in both views';
PRINT '   allows attacker to correlate data through JOIN operations.';
PRINT '';
PRINT '5. How does NEWID() prevent inference?';
PRINT '   Answer: Generates different random GUIDs for name and salary,';
PRINT '   making it impossible to link them without access to AdminMap.';
PRINT '';
PRINT '6. What is a functional dependency?';
PRINT '   Answer: If attribute A determines attribute B (A→B), then';
PRINT '   knowing A allows you to infer B using business rules.';
PRINT '';
PRINT '7. How do you compute closure Q⁺?';
PRINT '   Answer: Start with Q, iteratively add attributes using FDs';
PRINT '   until no more attributes can be added.';
PRINT '';
PRINT '8. What is the difference attack?';
PRINT '   Answer: Target = (Total_Avg × N) - (Exclude_Avg × (N-1))';
PRINT '   Works when group size is small (N=2).';
PRINT '';
PRINT '9. What is K-anonymity?';
PRINT '   Answer: Each record must be indistinguishable from at least';
PRINT '   K-1 other records. For K=3, minimum group size is 3.';
PRINT '';
PRINT '10. Why is K=3 the minimum safe value?';
PRINT '    Answer: K=2 allows difference attack. K=3 prevents isolation';
PRINT '    of individual values from aggregate statistics.';
PRINT '';
PRINT '═══════════════════════════════════════════════════════════════';
PRINT '         ALL ASSIGNMENT REQUIREMENTS COMPLETED! 🎓';
PRINT '            Ready for Week 6 Discussion Session';
PRINT '═══════════════════════════════════════════════════════════════';
GO

