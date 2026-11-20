import Foundation
import Capacitor
import CryptoKit
import Security

@objc(BgsSecurePlugin)
public class BgsSecurePlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "BgsSecurePlugin"
    public let jsName = "BgsSecure"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "hmacSeal", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "available", returnType: CAPPluginReturnPromise)
    ]

    private let service = "com.benguosa.save.seal"
    private let account = "v1"

    @objc func available(_ call: CAPPluginCall) {
        call.resolve(["value": keyData() != nil])
    }

    @objc func hmacSeal(_ call: CAPPluginCall) {
        guard let payload = call.getString("payload"), let key = keyData() else {
            call.reject("secure key unavailable")
            return
        }
        let symmetric = SymmetricKey(data: key)
        let code = HMAC<SHA256>.authenticationCode(for: Data(payload.utf8), using: symmetric)
        let value = "n1:" + Data(code).base64EncodedString()
        call.resolve(["value": value])
    }

    private func keyData() -> Data? {
        if let existing = readKeychain() { return existing }
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return nil }
        let data = Data(bytes)
        guard saveKeychain(data) else { return nil }
        return data
    }

    private func query() -> [String: Any] {
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }

    private func readKeychain() -> Data? {
        var q = query()
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data, data.count == 32 else { return nil }
        return data
    }

    private func saveKeychain(_ data: Data) -> Bool {
        var q = query()
        SecItemDelete(q as CFDictionary)
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        q[kSecAttrSynchronizable as String] = false
        return SecItemAdd(q as CFDictionary, nil) == errSecSuccess
    }
}
