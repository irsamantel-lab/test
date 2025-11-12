-- Table: user
CREATE TABLE user (firstName TEXT, lastName TEXT, email TEXT, phone TEXT, expertiseId TEXT, username TEXT NOT NULL PRIMARY KEY, token TEXT NOT NULL, countryCode TEXT);

-- Table: books
CREATE TABLE books (id TEXT NOT NULL PRIMARY KEY, orderNumber INTEGER NOT NULL);

-- Table: config
CREATE TABLE config (expireDate DATETIME NOT NULL, isExpired BOOLEAN NOT NULL, isDisabled BOOLEAN NOT NULL, lastSync DATETIME NOT NULL, lastModifiedInfo DATETIME NOT NULL, version REAL NOT NULL, booksPath TEXT NOT NULL, advertTitle TEXT, advertDescriptions TEXT, advertUrl TEXT, advertIcon TEXT, whatsappAvailable BOOLEAN NOT NULL DEFAULT true, facebookAvailable BOOLEAN NOT NULL DEFAULT true, telegramAvailable BOOLEAN NOT NULL DEFAULT true, fontSize DOUBLE, freeMode BOOLEAN NOT NULL DEFAULT false);

-- Table: contentInfo
CREATE TABLE contentInfo (contentId TEXT NOT NULL, bookId TEXT NOT NULL, highlights TEXT, notes TEXT, state INTEGER NOT NULL DEFAULT 1, syncWithServer BOOLEAN NOT NULL DEFAULT false);

-- Table: favorites
CREATE TABLE favorites (contentId TEXT NOT NULL, contentTitle TEXT NOT NULL, bookId TEXT NOT NULL, bookTitle TEXT NOT NULL, state INTEGER NOT NULL DEFAULT 1, syncWithServer BOOLEAN NOT NULL DEFAULT false, insertDate DATETIME NOT NULL DEFAULT '2018-01-01 00:00:00', PRIMARY KEY (contentId, bookId)) WITHOUT ROWID;

-- Table: history
CREATE TABLE history (dateAndTime DATETIME NOT NULL, bookId TEXT, bookName TEXT, searchedText TEXT, clickedTitle TEXT, clickedItemId TEXT, syncedWithServer BOOLEAN DEFAULT false);

