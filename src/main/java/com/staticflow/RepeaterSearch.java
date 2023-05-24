package com.staticflow;


import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

/**
 * The entry point for a Burp Suite extension that adds a custom search bar to the Repeater tab.
 * This extension allows users to search through the request body and/or the response body of requests
 * using a simple string or a regular expression (regex).
 *
 * The `RepeaterSearch` class implements the `BurpExtension` and `ExtensionUnloadingHandler` interfaces,
 * allowing it to handle extension initialization and unloading events.
 *
 * Upon initialization, the `initialize` method registers the extension's unloading handler, sets the
 * necessary callbacks, and adds the search bar to the Repeater tab.
 *
 * When the extension is unloaded, the `extensionUnloaded` method is called to perform any necessary
 * clean-up operations.
 *
 * @see BurpExtension
 * @see ExtensionUnloadingHandler
 */
public class RepeaterSearch implements BurpExtension, ExtensionUnloadingHandler {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().registerUnloadingHandler(this);
        ExtensionState.getInstance().setCallbacks(api);
        Utils.addSearchBarToRepeaterTab();
    }

    @Override
    public void extensionUnloaded() {
        Utils.cleanUpExtension();
    }

}