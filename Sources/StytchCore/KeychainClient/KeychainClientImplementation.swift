import CryptoKit
import Foundation
import Security
#if !os(tvOS)
import LocalAuthentication
#endif
#if os(iOS)
import UIKit
#endif

let ENCRYPTEDUSERDEFAULTSKEYNAME = "EncryptedUserDefaultsKey"

final class KeychainClientImplementation: KeychainClient {
    static let shared = KeychainClientImplementation()
    private let queue: DispatchQueue
    private let queueKey = DispatchSpecificKey<Void>()
    private var cachedEncryptionKey: SymmetricKey?
    var didInitializeKeychainData = false
    var encryptionKey: SymmetricKey? {
        (try? safelyEnqueue {
            if let cachedEncryptionKey {
                return cachedEncryptionKey
            }
            // The keychain read itself is the authoritative availability test: a locked keychain fails the
            // read with an error, which we treat as transient. We deliberately do not consult
            // UIApplication.shared.isProtectedDataAvailable here - it is a main-thread-only API and this
            // getter runs on the keychain queue.
            try? getEncryptionKey()
            if cachedEncryptionKey != nil {
                didInitializeKeychainData = true
            }
            return cachedEncryptionKey
        })
    }

    // Cached, thread-safe view of protected data availability. UIApplication.shared.isProtectedDataAvailable
    // is a main-thread-only API, so we seed the value from the main thread and keep it current via the
    // protected data notifications. nil means the value has not been seeded yet.
    private let protectedDataLock = NSLock()
    private var protectedDataAvailable: Bool?

    private var isOnQueue: Bool {
        DispatchQueue.getSpecific(key: queueKey) != nil
    }

    #if !os(tvOS) && !os(watchOS)
    // Shared reusable private context for the keychain client,
    // always configured with interactionNotAllowed = true
    private let contextWithoutUI = LAContext()
    #endif

    private init() {
        queue = DispatchQueue(label: "StytchKeychainClientQueue")
        queue.setSpecific(key: queueKey, value: ())
        #if !os(tvOS) && !os(watchOS)
        contextWithoutUI.interactionNotAllowed = true
        #endif
        #if os(iOS)
        NotificationCenter.default.addObserver(forName: UIApplication.protectedDataDidBecomeAvailableNotification, object: nil, queue: nil) { [weak self] _ in
            self?.setProtectedDataAvailable(true)
        }
        NotificationCenter.default.addObserver(forName: UIApplication.protectedDataWillBecomeUnavailableNotification, object: nil, queue: nil) { [weak self] _ in
            self?.setProtectedDataAvailable(false)
        }
        refreshProtectedDataAvailability()
        #endif
    }

    func safelyEnqueue<T>(_ block: () throws -> T) throws -> T {
        if isOnQueue {
            return try block()
        } else {
            return try queue.sync { try block() }
        }
    }

    func getEncryptionKey() throws {
        try safelyEnqueue {
            let result = try getFirstQueryResult(KeychainItem.encryptionKey)
            guard let result else {
                // The keychain reported the key as missing. Only trust that verdict and create a new key when
                // protected data is confirmed available; otherwise treat this as a transient failure so we
                // never overwrite an existing key that is merely unreadable right now.
                guard isProtectedDataKnownAvailable else {
                    refreshProtectedDataAvailability()
                    StytchConsoleLogger.error(message: "Encryption key not found in keychain, but protected data availability is not confirmed - deferring key creation")
                    throw KeychainError.encryptionKeyUnavailable
                }
                let data = SymmetricKey(size: .bits256).withUnsafeBytes {
                    Data(Array($0))
                }
                try setValueForItem(value: .init(data: data, account: ENCRYPTEDUSERDEFAULTSKEYNAME, label: nil, generic: nil, accessPolicy: nil), item: .encryptionKey)
                cachedEncryptionKey = SymmetricKey(data: data)
                return
            }
            cachedEncryptionKey = SymmetricKey(data: result.data)
        }
    }

    private var isProtectedDataKnownAvailable: Bool {
        #if os(iOS)
        protectedDataLock.lock()
        defer { protectedDataLock.unlock() }
        return protectedDataAvailable == true
        #else
        return true
        #endif
    }

    private func setProtectedDataAvailable(_ available: Bool) {
        protectedDataLock.lock()
        protectedDataAvailable = available
        protectedDataLock.unlock()
    }

    private func refreshProtectedDataAvailability() {
        #if os(iOS)
        if Thread.isMainThread {
            setProtectedDataAvailable(UIApplication.shared.isProtectedDataAvailable)
        } else {
            DispatchQueue.main.async { [weak self] in
                self?.setProtectedDataAvailable(UIApplication.shared.isProtectedDataAvailable)
            }
        }
        #endif
    }

    // swiftlint:disable:next function_body_length
    func getQueryResults(item: KeychainItem) throws -> [KeychainQueryResult] {
        try safelyEnqueue {
            var result: CFTypeRef?
            var query = item.getQuery
            #if !os(tvOS) && !os(watchOS)
            query[kSecUseAuthenticationContext] = LocalAuthenticationContextManager.laContext
            #endif
            var status: OSStatus?
            if item.kind == .privateKey {
                // recursively check each potential type of access control flag
                var potentialFlags: [SecAccessControlCreateFlags] = [
                    [.userPresence],
                    [.biometryCurrentSet],
                ]

                #if os(macOS)
                potentialFlags.append([.biometryCurrentSet, .or, .watch])
                #endif

                for flags in potentialFlags {
                    var error: Unmanaged<CFError>?
                    defer {
                        error?.release()
                    }
                    let accessControl = SecAccessControlCreateWithFlags(
                        nil,
                        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                        flags,
                        &error
                    )
                    var newQuery = query
                    newQuery[kSecAttrAccessControl] = accessControl
                    status = SecItemCopyMatching(newQuery as CFDictionary, &result)
                    if status == errSecSuccess {
                        break
                    }
                }
            } else if item.kind == .encryptionKey {
                var newQuery = query
                newQuery[kSecAttrAccount] = ENCRYPTEDUSERDEFAULTSKEYNAME
                status = SecItemCopyMatching(newQuery as CFDictionary, &result)
            } else {
                status = SecItemCopyMatching(query as CFDictionary, &result)
            }

            if let status = status, ![errSecSuccess, errSecItemNotFound].contains(status) {
                throw KeychainError.unhandledError(status: status)
            }
            guard case errSecSuccess = status else {
                return []
            }
            guard let results = result as? [[CFString: Any]] else {
                throw KeychainError.resultNotArray
            }
            return try results.compactMap { dict in
                guard let data = dict[kSecValueData] as? Data else {
                    throw KeychainError.resultNotData
                }
                guard let account = dict[kSecAttrAccount] as? String else {
                    throw KeychainError.resultMissingAccount
                }
                guard let createdAt = dict[kSecAttrCreationDate] as? Date, let modifiedAt = dict[kSecAttrModificationDate] as? Date else {
                    throw KeychainError.resultMissingDates
                }
                let label = dict[kSecAttrLabel] as? String
                let generic = dict[kSecAttrGeneric] as? Data
                return KeychainQueryResult(
                    data: data,
                    createdAt: createdAt,
                    modifiedAt: modifiedAt,
                    label: label,
                    account: account,
                    generic: generic
                )
            }
        }
    }

    func valueExistsForItem(item: KeychainItem) -> Bool {
        let exists = try? safelyEnqueue {
            var result: CFTypeRef?
            var query = item.getQuery
            #if !os(tvOS) && !os(watchOS)
            query[kSecUseAuthenticationContext] = contextWithoutUI
            #endif
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            return [errSecSuccess, errSecInteractionNotAllowed].contains(status)
        }
        return exists == true
    }

    func setValueForItem(value: KeychainItem.Value, item: KeychainItem) throws {
        try safelyEnqueue {
            let status: OSStatus
            var query = item.baseQuery
            #if !os(tvOS) && !os(watchOS)
            query[kSecUseAuthenticationContext] = LocalAuthenticationContextManager.laContext
            #endif
            if valueExistsForItem(item: item) {
                let queryDict = query as CFDictionary
                let attributesToUpdate = item.updateQuerySegment(for: value) as CFDictionary
                status = SecItemUpdate(queryDict, attributesToUpdate)
            } else {
                status = SecItemAdd(item.insertQuery(value: value), nil)
            }
            if status != errSecSuccess {
                throw KeychainError.unhandledError(status: status)
            }
        }
    }

    func removeItem(item: KeychainItem) throws {
        try safelyEnqueue {
            let tryRemovingItem: (CFDictionary) throws -> Void = { query in
                let status = SecItemDelete(query)
                guard [errSecSuccess, errSecItemNotFound].contains(status) else {
                    throw KeychainError.unhandledError(status: status)
                }
            }
            var parameters: [CFString: AnyObject] = [kSecAttrSynchronizable: kSecAttrSynchronizableAny]
            if item.kind == .encryptionKey {
                parameters[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlock
                try tryRemovingItem(item.baseQuery.merging(parameters))
            } else {
                // recursively check each potential type of access control flag
                var potentialFlags: [SecAccessControlCreateFlags] = [
                    [.userPresence],
                    [.biometryCurrentSet],
                ]
                #if os(macOS)
                potentialFlags.append([.biometryCurrentSet, .or, .watch])
                #endif
                try potentialFlags.forEach { flags in
                    var newParameters = parameters
                    var error: Unmanaged<CFError>?
                    defer {
                        error?.release()
                    }
                    let accessControl = SecAccessControlCreateWithFlags(
                        nil,
                        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                        flags,
                        &error
                    )
                    newParameters[kSecAttrAccessControl] = accessControl
                    try tryRemovingItem(item.baseQuery.merging(newParameters))
                }
            }
        }
    }
}
