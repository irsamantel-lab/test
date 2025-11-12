
async function decodeRequest(encodedData) {
    const base64Decoded = atob(encodedData);
    const compressedData = new Uint8Array(base64Decoded.length).map((_, i) => base64Decoded.charCodeAt(i));
    const decompressionStream = new DecompressionStream('deflate');
    const writer = decompressionStream.writable.getWriter();
    writer.write(compressedData);
    writer.close();
    const decompressedData = await new Response(decompressionStream.readable).arrayBuffer();
    const jsonString = new TextDecoder().decode(decompressedData);
    return JSON.parse(jsonString);
}

async function encryptResponse(payload, password) {
    const passwordBytes = new TextEncoder().encode(password);
    const salt = crypto.getRandomValues(new Uint8Array(8));
    const { key, iv } = await deriveKeyAndIv(passwordBytes, salt);
    const plaintextBytes = new TextEncoder().encode(JSON.stringify(payload));
    const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "AES-CBC" }, false, ["encrypt"]);
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, cryptoKey, plaintextBytes);
    const saltedMagic = new TextEncoder().encode("Salted__");
    const finalEncryptedData = new Uint8Array(saltedMagic.length + salt.length + ciphertext.byteLength);
    finalEncryptedData.set(saltedMagic);
    finalEncryptedData.set(salt, saltedMagic.length);
    finalEncryptedData.set(new Uint8Array(ciphertext), saltedMagic.length + salt.length);
    const binaryString = Array.from(finalEncryptedData).map(byte => String.fromCharCode(byte)).join('');
    return btoa(binaryString);
}

async function deriveKeyAndIv(password, salt) {
    const keySize = 32;
    const ivSize = 16;
    const requiredLength = keySize + ivSize;
    let derivedBytes = new Uint8Array(requiredLength);
    let bytesWritten = 0;
    let lastHash = new Uint8Array(0);
    while (bytesWritten < requiredLength) {
        const dataToHash = new Uint8Array(lastHash.length + password.length + salt.length);
        dataToHash.set(lastHash);
        dataToHash.set(password, lastHash.length);
        dataToHash.set(salt, lastHash.length + password.length);
        const hashBuffer = await crypto.subtle.digest('MD5', dataToHash);
        lastHash = new Uint8Array(hashBuffer);
        const bytesToCopy = Math.min(lastHash.length, requiredLength - bytesWritten);
        derivedBytes.set(lastHash.slice(0, bytesToCopy), bytesWritten);
        bytesWritten += bytesToCopy;
    }
    return {
        key: derivedBytes.slice(0, keySize),
        iv: derivedBytes.slice(keySize, requiredLength),
    };
}
// --- END: CRYPTO AND ENCODING HELPERS ---


// --- Main Worker Logic & Router ---
export default {
    async fetch(request, env, ctx) {
        if (request.method === 'OPTIONS') {
            return handleOptions(request);
        }

        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;

        try {
            // User Authentication & Account
            if (path.endsWith('/app/login') && method === 'POST') return await handleLogin(request, env);
            if (path.endsWith('/app/user/forgotAccount') && method === 'POST') return await handleForgotAccount(request, env);
            if (path.endsWith('/app/user/update') && method === 'POST') return await handleUserUpdate(request, env);

            // Synchronization
            if (path.endsWith('/app/sync') && method === 'POST') return await handleSync(request, env);
            if (path.endsWith('/app/syncUserBooks') && method === 'POST') return await handleSyncUserBooks(request, env);
            if (path.endsWith('/app/syncUserFavorites') && method === 'POST') return await handleSyncUserFavorites(request, env);
            if (path.endsWith('/app/syncHistory') && method === 'POST') return await handleSyncHistory(request, env);

            // Book & Content Management
            if (path.endsWith('/app/book/search') && method === 'GET') return await handleBookSearch(request, env);
            if (path.endsWith('/app/book/update') && method === 'POST') return await handleBookUpdate(request, env);

            // Miscellaneous
            if (path.endsWith('/app/latestVersion') && method === 'GET') return await handleLatestVersion(request, env);
            if (path.endsWith('/app/advert/trigger') && method === 'POST') return await handleAdvertTrigger(request, env);

            return jsonResponse({ error: "Endpoint not found" }, 404);
        } catch (error) {
            console.error(`Worker Error on ${path}: ${error.stack}`);
            return jsonResponse({ error: "Internal Server Error", message: error.message }, 500);
        }
    },
};

// --- Endpoint Handlers ---


async function handleLogin(request, env) {
    const { data } = await request.json();
    const { username, password, deviceId } = await decodeRequest(data);
    
    const user = await env.DB.prepare("SELECT * FROM Users WHERE username = ?").bind(username).first();
    if (!user) {
        return jsonResponse({ error: "Invalid username." }, 200);
    }

    const passwordHash = await sha256(user.salt + password);
    if (passwordHash !== user.hashedPassword) {
        return jsonResponse({ error: "Invalid password." }, 200);
    }

    const newToken = crypto.randomUUID();
    await env.DB.prepare("UPDATE Users SET token = ?, deviceId = ? WHERE username = ?")
        .bind(newToken, deviceId, username).run();

    // --- NEW: Fetch UserBooks and History ---
    const userBooksResult = await env.DB.prepare("SELECT bookId as id, installedVersion as version FROM UserBooks WHERE username = ?").bind(username).all();
    const historyResult = await env.DB.prepare("SELECT * FROM History WHERE username = ? ORDER BY dateAndTime DESC LIMIT 100").bind(username).all(); // Limit to recent 100
    const favoritesResult = await env.DB.prepare("SELECT * FROM Favorites WHERE username = ?").bind(username).all();
    
    const responsePayload = {
        user: {
            firstName: user.firstName, lastName: user.lastName, phone: user.phone,
            expertiseId: user.expertiseId, username: user.username, token: newToken,
            countryCode: user.countryCode, active: user.active === 1
        },
        config: {
            expireDate: user.expireDate, isExpired: new Date() > new Date(user.expireDate),
            isDisabled: user.isDisabled === 1, lastSync: Date.now(), lastModifiedInfo: user.lastModifiedInfo,
            advertTitle: null, advertUrl: null, whatsappAvailable: true, facebookAvailable: false,
            telegramAvailable: true
        },
        // --- Populated with fetched data ---
        books: userBooksResult.results || [],
        favorites: favoritesResult.results || [],
        histories: historyResult.results || [],
        latestVersion: 5.8,
        success: true
    };
    
    const encryptedData = await encryptResponse(responsePayload, deviceId);
    return jsonResponse({ success: true, data: encryptedData });
}

async function handleForgotAccount(request, env) {
    const { data } = await request.json();
    const { phone } = await decodeRequest(data);
    console.log(`Account recovery requested for phone: ${phone}`);
    const encryptedData = await encryptResponse({ success: true, message: "Your account information has been sent." }, "placeholder-device-id");
    return jsonResponse({ success: true, data: encryptedData });
}

async function handleUserUpdate(request, env) {
    const { data } = await request.json();
    const payload = await decodeRequest(data);
    
    // Authenticate the user with their current token and username. This is our only security check needed.
    const user = await authenticateUser(payload.token, payload.username, env.DB);
    if (!user) {
        return jsonResponse({ error: "login" }, 200);
    }

    // --- Part 1: Handle Basic Profile Updates ---
    const fieldsToUpdate = ['firstName', 'lastName', 'phone', 'email', 'expertiseId', 'countryCode'];
    const updates = [];
    const values = [];

    fieldsToUpdate.forEach(field => {
        if (payload[field] !== undefined && payload[field] !== user[field]) {
            updates.push(`${field} = ?`);
            values.push(payload[field]);
        }
    });

    // --- Part 2: Handle Secure Password Update (No Current Password Required) ---
    const hasPasswordChange = payload.newPassword;

    if (hasPasswordChange) {
        if (payload.newPassword !== payload.confirmNewPassword) {
            return jsonResponse({ error: "New passwords do not match." }, 200);
        }
        // Generate a new salt and hash for the new password
        const newSalt = crypto.randomUUID();
        const newHashedPassword = await sha256(newSalt + payload.newPassword);
        updates.push("salt = ?");
        updates.push("hashedPassword = ?");
        values.push(newSalt, newHashedPassword);
    }
    
    // --- USERNAME CHANGES ARE DISABLED ---
    // Any `newUsername` field in the payload will be ignored.

    // --- Part 3: Execute the Database Update ---
    if (updates.length > 0) {
        // The WHERE clause targets the authenticated user.
        values.push(user.username);
        const sql = `UPDATE Users SET ${updates.join(', ')} WHERE username = ?`;
        
        try {
            await env.DB.prepare(sql).bind(...values).run();
        } catch (e) {
            console.error("User update failed:", e.message);
            return jsonResponse({ error: "Failed to update user information.", message: e.message }, 500);
        }
    }

    // Respond with success
    const encryptedData = await encryptResponse({ success: true }, user.deviceId);
    return jsonResponse({ success: true, data: encryptedData });
}

async function handleSync(request, env) {
    const { data } = await request.json();
    const { username, token } = await decodeRequest(data);
    const user = await authenticateUser(token, username, env.DB);
    if (!user) return jsonResponse({ error: "login", force: "logout" }, 200);

    const responsePayload = {
        config: {
            expireDate: user.expireDate, isExpired: new Date() > new Date(user.expireDate),
            isDisabled: user.isDisabled === 1, lastSync: Date.now(), lastModifiedInfo: user.lastModifiedInfo
        },
        user: {},
        latestVersion: 5.8
    };
    const encryptedData = await encryptResponse(responsePayload, user.deviceId);
    return jsonResponse({ success: true, data: encryptedData });
}

async function handleSyncUserBooks(request, env) {
    const { data } = await request.json();
    const { username, token, books } = await decodeRequest(data);
    const user = await authenticateUser(token, username, env.DB);
    if (!user) return jsonResponse({ error: "login" }, 200);

    if (books && books.length > 0) {
        const batch = [];
        // This logic is sound: delete all existing books for the user and re-insert the new list.
        const deleteStmt = env.DB.prepare("DELETE FROM UserBooks WHERE username = ?");
        batch.push(deleteStmt.bind(username));
        
        const insertStmt = env.DB.prepare("INSERT INTO UserBooks (username, bookId, installedVersion) VALUES (?, ?, ?)");
        books.forEach(book => batch.push(insertStmt.bind(username, book.id, book.version)));
        
        await env.DB.batch(batch);
    }
    
    // --- NEW: Fetch and return the complete list of user books ---
    const userBooksResult = await env.DB.prepare("SELECT bookId as id, installedVersion as version FROM UserBooks WHERE username = ?").bind(username).all();

    const encryptedData = await encryptResponse({ success: true, books: userBooksResult.results || [] }, user.deviceId);
    return jsonResponse({ success: true, data: encryptedData });
}

async function handleSyncUserFavorites(request, env) {
    const { data } = await request.json();
    const { username, token, inserted, removed, newContentInfoInserted, newContentInfoRemoved } = await decodeRequest(data);
    const user = await authenticateUser(token, username, env.DB);
    if (!user) return jsonResponse({ error: "login" }, 200);

    const batch = [];

    // --- Part 1: Logic to Handle Favorites (Bookmarks) ---
    if (inserted && inserted.length > 0) {
        const insertStmt = env.DB.prepare(
            "REPLACE INTO Favorites (username, contentId, bookId, contentTitle, bookTitle, insertDate) VALUES (?, ?, ?, ?, ?, ?)"
        );
        inserted.forEach(fav => {
            batch.push(insertStmt.bind(username, fav.contentId, fav.bookId, fav.contentTitle, fav.bookTitle, fav.insertDate));
        });
    }
    if (removed && removed.length > 0) {
        const deleteStmt = env.DB.prepare(
            "DELETE FROM Favorites WHERE username = ? AND contentId = ? AND bookId = ?"
        );
        removed.forEach(fav => {
            batch.push(deleteStmt.bind(username, fav.contentId, fav.bookId));
        });
    }

    // --- Part 2: Logic to Handle ContentInfo (Notes & Highlights) ---
    if (newContentInfoInserted && newContentInfoInserted.length > 0) {
        const insertContentStmt = env.DB.prepare(
            "REPLACE INTO ContentInfo (username, contentId, bookId, highlights, notes) VALUES (?, ?, ?, ?, ?)"
        );
        newContentInfoInserted.forEach(info => {
            // This will save the notes and/or highlights sent from the client.
            batch.push(insertContentStmt.bind(username, info.contentId, info.bookId, info.highlights, info.notes));
        });
    }
    if (newContentInfoRemoved && newContentInfoRemoved.length > 0) {
        const deleteContentStmt = env.DB.prepare(
            "DELETE FROM ContentInfo WHERE username = ? AND contentId = ? AND bookId = ?"
        );
        newContentInfoRemoved.forEach(info => {
            batch.push(deleteContentStmt.bind(username, info.contentId, info.bookId));
        });
    }

    // Execute all INSERT/REPLACE/DELETE operations in one go.
    if (batch.length > 0) {
        await env.DB.batch(batch);
    }

    // --- Part 3: Retrieve and Return Updated Data ---
    // After saving, fetch the complete lists for the user.
    const favoritesResult = await env.DB.prepare("SELECT * FROM Favorites WHERE username = ?").bind(username).all();
    const contentInfoResult = await env.DB.prepare("SELECT * FROM ContentInfo WHERE username = ?").bind(username).all();
    
    // The client expects a `contentInfoList` array in the response.
    const responsePayload = {
        favorites: favoritesResult.results || [],
        contentInfoList: contentInfoResult.results || []
    };

    const encryptedData = await encryptResponse(responsePayload, user.deviceId);
    return jsonResponse({ success: true, data: encryptedData });
}

async function handleSyncHistory(request, env) {
    const { data } = await request.json();
    const { username, token, newHistoryInsertedList } = await decodeRequest(data);
    const user = await authenticateUser(token, username, env.DB);
    if (!user) return jsonResponse({ error: "login" }, 200);

    // This logic is correct for inserting new history items.
    if (newHistoryInsertedList && newHistoryInsertedList.length > 0) {
        const stmt = env.DB.prepare("INSERT INTO History (username, dateAndTime, bookId, bookName, searchedText, clickedTitle, clickedItemId) VALUES (?, ?, ?, ?, ?, ?, ?)");
        const batch = newHistoryInsertedList.map(h => stmt.bind(username, h.dateAndTime, h.bookId, h.bookName, h.searchedText, h.clickedTitle, h.clickedItemId));
        await env.DB.batch(batch);
    }

    // --- NEW: Fetch and return the user's recent history ---
    const historyResult = await env.DB.prepare("SELECT * FROM History WHERE username = ? ORDER BY dateAndTime DESC LIMIT 100").bind(username).all();

    const encryptedData = await encryptResponse({ histories: historyResult.results || [] }, user.deviceId);
    return jsonResponse({ success: true, data: encryptedData });
}

async function handleBookSearch(request, env) {
    const url = new URL(request.url);
    const params = url.searchParams;

    const queryParam = params.get('query') || '';
    const PAGE_SIZE = 20; // The number of books to return per page.

    // --- Pagination Validation ---
    // Sanitize the 'page' parameter to ensure it is a non-negative integer.
    let page = parseInt(params.get('page') || '0', 10);
    if (isNaN(page) || page < 0) {
        page = 0; // Default to the first page if the input is invalid (e.g., negative or not a number).
    }
    const offset = page * PAGE_SIZE;
    // --- End of Validation ---

    let querySql = "SELECT * FROM Books";
    let whereClauses = [];
    const bindings = [];

    // Check if the query parameter is a JSON string for advanced filters
    if (queryParam.startsWith('{')) {
        try {
            const advancedQuery = JSON.parse(queryParam);
            
            if (advancedQuery.title && advancedQuery.title.trim() !== '') {
                whereClauses.push("title LIKE ?");
                bindings.push(`%${advancedQuery.title}%`);
            }

            if (advancedQuery.category && advancedQuery.category.length > 0) {
                const categoryClauses = advancedQuery.category.map(() => "categories LIKE ?").join(" OR ");
                whereClauses.push(`(${categoryClauses})`);
                advancedQuery.category.forEach(cat => bindings.push(`%${cat}%`));
            }
        } catch (e) {
            // Fallback for malformed JSON
            whereClauses.push("title LIKE ?");
            bindings.push(`%${queryParam}%`);
        }
    } else if (queryParam) {
        // Handle simple text search
        whereClauses.push("title LIKE ?");
        bindings.push(`%${queryParam}%`);
    }

    if (whereClauses.length > 0) {
        querySql += " WHERE " + whereClauses.join(" AND ");
    }

    // Add ordering and pagination to the final query
    querySql += " ORDER BY showOnTop DESC, title ASC LIMIT ? OFFSET ?";
    bindings.push(PAGE_SIZE, offset);

    try {
        const stmt = env.DB.prepare(querySql).bind(...bindings);
        const { results } = await stmt.all();

        // This will correctly return an empty array for pages that have no results.
        return jsonResponse({ success: true, result: results || [] });
    } catch (e) {
        console.error("Database query failed:", e.message);
        console.error("Failing Query:", querySql);
        console.error("Failing Bindings:", bindings);
        return jsonResponse({ success: false, error: "Database query failed", message: e.message }, 500);
    }
}

async function handleBookUpdate(request, env) {
    const { data } = await request.json();
    const { username, token } = await decodeRequest(data);
    const user = await authenticateUser(token, username, env.DB);
    if (!user) return jsonResponse({ error: "login" }, 200);
    
    // This is a placeholder as we don't have the book content
    const encryptedData = await encryptResponse({ info: "You are using the latest version." }, user.deviceId);
    return jsonResponse({ success: true, data: encryptedData });
}

async function handleLatestVersion(request, env) {
    return jsonResponse({ success: true, latestVersion: 5.8 });
}

async function handleAdvertTrigger(request, env) {
    // Just acknowledge the request
    return jsonResponse({ success: true });
}

// --- Utility Functions ---
async function authenticateUser(token, username, db) {
    if (!token || !username) return null;
    return await db.prepare("SELECT * FROM Users WHERE username = ? AND token = ?").bind(username, token).first();
}

async function sha256(message) {
    const data = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), { status, headers: corsHeaders() });
}

function corsHeaders() {
    return {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Origin, X-Requested-With, Content-Type, Accept, Cache-control, Pragma',
    };
}

function handleOptions(request) {
    return new Response(null, { headers: corsHeaders() });
}