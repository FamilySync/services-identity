CREATE TABLE IF NOT EXISTS `__EFMigrationsHistory` (
    `MigrationId` varchar(150) CHARACTER SET utf8mb4 NOT NULL,
    `ProductVersion` varchar(32) CHARACTER SET utf8mb4 NOT NULL,
    CONSTRAINT `PK___EFMigrationsHistory` PRIMARY KEY (`MigrationId`)
) CHARACTER SET=utf8mb4;

START TRANSACTION;

ALTER DATABASE CHARACTER SET utf8mb4;

CREATE TABLE `Identities` (
    `ID` char(36) COLLATE ascii_general_ci NOT NULL,
    `FullName` longtext CHARACTER SET utf8mb4 NOT NULL,
    `Username` longtext CHARACTER SET utf8mb4 NOT NULL,
    `Password` longtext CHARACTER SET utf8mb4 NOT NULL,
    CONSTRAINT `PK_Identities` PRIMARY KEY (`ID`)
) CHARACTER SET=utf8mb4;

INSERT INTO `__EFMigrationsHistory` (`MigrationId`, `ProductVersion`)
VALUES ('20240328110149_InitialCreate', '8.0.3');

COMMIT;

START TRANSACTION;

ALTER TABLE `Identities` MODIFY COLUMN `Username` varchar(255) CHARACTER SET utf8mb4 NOT NULL;

ALTER TABLE `Identities` ADD `Email` varchar(255) CHARACTER SET utf8mb4 NOT NULL DEFAULT '';

CREATE UNIQUE INDEX `IX_Identities_Email` ON `Identities` (`Email`);

CREATE UNIQUE INDEX `IX_Identities_Username` ON `Identities` (`Username`);

INSERT INTO `__EFMigrationsHistory` (`MigrationId`, `ProductVersion`)
VALUES ('20240328110915_EnforceUniqueUsernameAndEmail', '8.0.3');

COMMIT;

