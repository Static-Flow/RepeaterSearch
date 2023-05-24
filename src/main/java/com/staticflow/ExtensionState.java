package com.staticflow;

import burp.api.montoya.MontoyaApi;
import main.java.com.staticflow.BurpGuiControl;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

/**
 * This Singleton class holds all custom state for the extension and provides a central means of accessing it.
 */
public class ExtensionState {
    private static final String REPEATER = "Repeater";


    private final Component repeaterComponent;
    private final JTabbedPane repeaterTabbedPane;
    private MontoyaApi callbacks;

    private static ExtensionState state;

    /**
     * Initializes the {@code ExtensionState} Singleton.
     *
     * This constructor obtains a reference to the Burp Suite Repeater tab swing component  using
     * {@link BurpGuiControl#getBaseBurpComponent}.
     * <br>
     * It then attaches a hierarchy listener to the Repeater tab component to determine when the Repeater tab
     * is in view.
     * <br>
     * When the Repeater tab is shown (using the {@link HierarchyEvent#SHOWING_CHANGED} flag of the hierarchy event), the
     * custom search bar created by this extension is set to be visible. This is because anytime a new tab is created in Repeater, Burp Suite recreates the
     * whole Repeater tab and JTabbedPane which for some magic swing reason sets our custom Component to be hidden.
     * <br>
     * Finally, this constructor obtains a reference to the {@link JTabbedPane} within the Repeater tab
     * component using {@link BurpGuiControl#findFirstComponentOfType}.
     */
    private ExtensionState() {
        this.repeaterComponent = BurpGuiControl.getBaseBurpComponent(REPEATER);
        this.repeaterComponent.addHierarchyListener(e -> {
            if ((e.getChangeFlags() & HierarchyEvent.SHOWING_CHANGED) != 0) {
                Container component = (Container) e.getComponent();
                if (component.isShowing()) {
                    component.getComponent(0).setVisible(true);
                }
            }
        });
        this.repeaterTabbedPane = (JTabbedPane) BurpGuiControl.findFirstComponentOfType((Container) repeaterComponent,JTabbedPane.class);
    }

    /*
        GETTERS/SETTERS BELOW
     */
    static ExtensionState getInstance() {
        if (state == null) {
            state = new ExtensionState();
        }
        return state;
    }

    public JTabbedPane getRepeaterTabbedPane() {
        return repeaterTabbedPane;
    }

    public Component getRepeaterComponent() {
        return this.repeaterComponent;
    }

    public MontoyaApi getCallbacks() {
        return this.callbacks;
    }

    public void setCallbacks(MontoyaApi callbacks) {
        this.callbacks = callbacks;
    }

}
