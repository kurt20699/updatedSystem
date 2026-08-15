/**
 * permissions.js
 * Shared role-based access control (RBAC) module for PRMSU Smart Campus Navigator.
 *
 * Works in TWO environments with the SAME rules:
 *   1. Browser  -> loaded via <script src="permissions.js"></script>, exposes window.Permissions
 *   2. Node.js  -> loaded via require('./permissions.js') in server.js
 *
 * Design: type-based access. Every building in campusData has a `type` field
 * (department | administration | facilities | office | landmark). Each role
 * is granted a whitelist of building types it may see, search, or navigate to.
 * Feature flags gate everything else (saved locations, route history, multi-stop).
 *
 * Extending later: add a new ROLES entry + a new ROLE_CONFIG block. Nothing
 * else needs to change — every consumer (client filtering, server middleware)
 * reads from ROLE_CONFIG.
 */

(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        // Node / CommonJS (server.js)
        module.exports = factory();
    } else {
        // Browser
        root.Permissions = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {

    const ROLES = Object.freeze({
        VISITOR: 'VISITOR',
        STUDENT: 'STUDENT',
        EMPLOYEE: 'EMPLOYEE',
        ADMIN: 'ADMIN'
    });

    // All known campusData location "type" values.
    const LOCATION_TYPES = Object.freeze([
        'department',
        'administration',
        'facilities',
        'office',
        'landmark'
    ]);

    // ── Per-role configuration ──────────────────────────────────────────
    // allowedTypes: 'all' | array of LOCATION_TYPES
    // features: capability flags checked throughout the app
    const ROLE_CONFIG = {
        [ROLES.VISITOR]: {
            allowedTypes: ['facilities', 'office', 'landmark', 'administration'],
            features: {
                saveLocations: false,
                routeHistory: false,
                // ✅ Visitors can now use Multiple Navigation. This does NOT
                // grant access to restricted building types — every entry
                // point into multi-stop (msSearchStop, addMarkers/updateMarkers
                // for map markers, handleSearch for the main search bar) still
                // filters through canAccessLocationType(role, type) using
                // allowedTypes above, so a Visitor can still only search for,
                // add, or navigate to buildings/rooms their role permits.
                // Restricted buildings simply never appear as markers or
                // search results in the first place, for single OR multi-stop.
                multiStop: true,
                roomInstructor: false,
                searchRooms: true,
                submitAnnouncements: false   // ← add this line
            }
        },
        [ROLES.STUDENT]: {
            allowedTypes: 'all',
            features: {
                saveLocations: true,
                routeHistory: true,
                multiStop: true,
                roomInstructor: true,
                searchRooms: true,
                submitAnnouncements: false   // ← add this line
            }
        },
        [ROLES.EMPLOYEE]: {
            allowedTypes: 'all',
            features: {
                saveLocations: true,
                routeHistory: true,
                multiStop: true,
                roomInstructor: true,
                searchRooms: true,
                submitAnnouncements: true    // ← add this line (Employees get the new privilege)
            }
        },
        [ROLES.ADMIN]: {
            allowedTypes: 'all',
            features: {
                saveLocations: true,
                routeHistory: true,
                multiStop: true,
                roomInstructor: true,
                searchRooms: true,
                submitAnnouncements: false   // ← add this line
            },
            isAdmin: true
        }
    };

    function normalizeRole(role) {
        const r = String(role || '').trim().toUpperCase();
        return ROLE_CONFIG[r] ? r : ROLES.VISITOR; // fail-closed: unknown role = most restricted
    }

    function getRoleConfig(role) {
        return ROLE_CONFIG[normalizeRole(role)];
    }

    /** Can this role view/search/navigate to a building of this type? */
    function canAccessLocationType(role, type) {
        const config = getRoleConfig(role);
        if (config.allowedTypes === 'all') return true;
        return config.allowedTypes.includes(type);
    }

    /** Can this role use a given feature flag (e.g. 'saveLocations')? */
    function canUseFeature(role, featureName) {
        const config = getRoleConfig(role);
        return Boolean(config.features && config.features[featureName]);
    }

    function isAdmin(role) {
        const config = getRoleConfig(role);
        return Boolean(config.isAdmin);
    }

    /**
     * Filter a campusData `locations` array down to what this role may see.
     * Does not mutate the input array.
     */
    function filterLocationsByRole(locations, role) {
        if (!Array.isArray(locations)) return [];
        return locations.filter(loc => canAccessLocationType(role, loc.type));
    }

    /**
     * Server-side guard: throws-free boolean check for a building "type"
     * string coming from a DB row (buildings.type) or campusData location.
     */
    function assertLocationTypeAllowed(role, type) {
        return canAccessLocationType(role, type);
    }

    return {
        ROLES,
        LOCATION_TYPES,
        ROLE_CONFIG,
        normalizeRole,
        getRoleConfig,
        canAccessLocationType,
        canUseFeature,
        isAdmin,
        filterLocationsByRole,
        assertLocationTypeAllowed
    };
});