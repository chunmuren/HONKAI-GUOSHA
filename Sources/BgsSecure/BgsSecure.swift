import Foundation
import CryptoKit

#if canImport(Security)
import Security
#endif

/// 存档封印的 iOS 原生实现。
/// 密钥保存在 Keychain，JavaScript 永远拿不到原始密钥，只能拿到 `n1:` 开头的 HMAC 结果。
public enum BgsSecureSeal {
    public static let service = "com.benguosa.save.seal"
    public static let account = "v1"
    public static let prefix = "n1:"

    /// 生成或读取本机 Keychain 中的 32 字节密钥。
    public static func keyData() -> Data? {
        if let existing = readKeychain() {
            return existing
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { return nil }
        let data = Data(bytes)
        guard saveKeychain(data) else { return nil }
        return data
    }

    /// 使用 Keychain 密钥对 payload 做 HMAC-SHA256，返回 `n1:Base64`。
    public static func seal(_ payload: String) -> String? {
        guard let key = keyData() else { return nil }
        return hmacBase64(key: key, payload: payload).map { prefix + $0 }
    }

    /// 纯计算版本，方便单元测试和跨平台复用。
    public static func hmacBase64(key: Data, payload: String) -> String? {
        let symmetric = SymmetricKey(data: key)
        let code = HMAC<SHA256>.authenticationCode(for: Data(payload.utf8), using: symmetric)
        return Data(code).base64EncodedString()
    }

    /// 常量时间比较，避免时序侧信道。
    public static func verify(_ seal: String, payload: String) -> Bool {
        guard seal.hasPrefix(prefix), let key = keyData() else { return false }
        guard let expected = hmacBase64(key: key, payload: payload) else { return false }
        let actual = String(seal.dropFirst(prefix.count))
        let a = Array(actual.utf8)
        let b = Array(expected.utf8)
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count { diff |= a[i] ^ b[i] }
        return diff == 0
    }

    // MARK: - Keychain

    private static func baseQuery() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        return query
    }

    private static func readKeychain() -> Data? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data, data.count == 32 else { return nil }
        return data
    }

    private static func saveKeychain(_ data: Data) -> Bool {
        var query = baseQuery()
        SecItemDelete(query as CFDictionary)

        query[kSecValueData as String] = data
        #if os(iOS)
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        #endif
        query[kSecAttrSynchronizable as String] = false
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }
}
