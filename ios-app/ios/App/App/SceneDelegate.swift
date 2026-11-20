import UIKit
import Capacitor

class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?

    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions) {
        guard let windowScene = scene as? UIWindowScene else { return }

        window = UIWindow(windowScene: windowScene)
        window?.rootViewController = CAPBridgeViewController()
        window?.makeKeyAndVisible()

        SceneDelegateProxy.shared.scene(scene, willConnectTo: session, options: connectionOptions)
    }

    func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
        SceneDelegateProxy.shared.scene(scene, openURLContexts: URLContexts)
    }

    func scene(_ scene: UIScene, continue userActivity: NSUserActivity) {
        SceneDelegateProxy.shared.scene(scene, continue: userActivity)
    }

    func sceneDidEnterBackground(_ scene: UIScene) {
        SceneDelegate.evaluate("window.__bgsNativeBackground&&window.__bgsNativeBackground(true)")
    }

    func sceneWillEnterForeground(_ scene: UIScene) {
        SceneDelegate.evaluate("window.__bgsNativeBackground&&window.__bgsNativeBackground(false)")
    }

    func sceneDidDisconnect(_ scene: UIScene) {
        SceneDelegate.evaluate("window.__bgsNativeExit&&window.__bgsNativeExit()")
    }

    static func evaluate(_ js: String) {
        DispatchQueue.main.async {
            let windows = UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .flatMap { $0.windows }
            let controller = windows.first(where: { $0.isKeyWindow })?.rootViewController
                ?? windows.first?.rootViewController
            if let bridgeController = controller as? CAPBridgeViewController {
                bridgeController.bridge?.webView?.evaluateJavaScript(js, completionHandler: nil)
            }
        }
    }
}
