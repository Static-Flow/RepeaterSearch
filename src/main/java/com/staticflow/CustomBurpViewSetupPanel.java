package com.staticflow;

import com.staticflow.BurpGuiControl;

import javax.swing.*;
import java.awt.*;

public class CustomBurpViewSetupPanel extends JPanel {
    private JFrame frame;
    public CustomBurpViewSetupPanel() {
        JButton button = new JButton("check");
        button.addActionListener(e -> {
            this.frame = new JFrame();
            Component proxy1 = BurpGuiControl.getProxyHTTPHistoryComponent();
            Component proxy2 = BurpGuiControl.getBaseBurpComponent("Repeater");
            frame.add(proxy1);
            frame.add(proxy2);
            frame.setSize(500,500);
            frame.setVisible(true);
        });
        add(button);
    }
}
