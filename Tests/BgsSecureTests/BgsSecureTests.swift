import XCTest
@testable import BgsSecure

final class BgsSecureTests: XCTestCase {
    func testHMACIsStable() throws {
        let key = Data((0..<32).map { UInt8($0) })
        let a = try XCTUnwrap(BgsSecureSeal.hmacBase64(key: key, payload: "BGS-SEAL|1|test"))
        let b = try XCTUnwrap(BgsSecureSeal.hmacBase64(key: key, payload: "BGS-SEAL|1|test"))
        XCTAssertEqual(a, b)
        XCTAssertFalse(a.isEmpty)
    }

    func testHMACDiffersByPayload() throws {
        let key = Data((0..<32).map { UInt8($0) })
        let a = try XCTUnwrap(BgsSecureSeal.hmacBase64(key: key, payload: "one"))
        let b = try XCTUnwrap(BgsSecureSeal.hmacBase64(key: key, payload: "two"))
        XCTAssertNotEqual(a, b)
    }

    func testSealPrefixWhenKeychainAvailable() throws {
        guard let seal = BgsSecureSeal.seal("BGS-SEAL|1|keychain") else {
            throw XCTSkip("Keychain unavailable in this environment")
        }
        XCTAssertTrue(seal.hasPrefix(BgsSecureSeal.prefix))
        XCTAssertTrue(BgsSecureSeal.verify(seal, payload: "BGS-SEAL|1|keychain"))
        XCTAssertFalse(BgsSecureSeal.verify(seal, payload: "BGS-SEAL|1|other"))
    }
}
