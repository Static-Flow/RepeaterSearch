package com.staticflow;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import burp.ITempFile;
import javassist.bytecode.ClassFile;
import javassist.bytecode.ClassFilePrinter;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;

public class RepeaterSearch implements IBurpExtender, IExtensionStateListener {

    private Component repeaterComponent;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        iBurpExtenderCallbacks.registerExtensionStateListener(this);
        this.repeaterComponent = BurpGuiControl.getBaseBurpComponent("Repeater");
        for(AWTEventListener l : Toolkit.getDefaultToolkit().getAWTEventListeners()) {
            InputStream in = l.getClass().getResourceAsStream('/'+l.getClass().getName().replace('.', '/')+".class");
            byte[] targetArray = new byte[0];
            try {
                targetArray = new byte[in.available()];
                in.read(targetArray);
                ITempFile temp = iBurpExtenderCallbacks.saveToTempFile(targetArray);

            } catch (IOException e) {
                e.printStackTrace();
            }

            System.out.println(l + " "+l.getClass() + " "+l.getClass().getCanonicalName());
            ClassFile c = new ClassFile(false,l.getClass().getName(),null);
            ClassFilePrinter.print(c,new PrintWriter(System.out, true));
        }
        //BurpGuiControl.printChildrenComponentsInputMaps(BurpGuiControl.getRootPane().getParent(),0,25);

        BurpGuiControl.getRootPane().getToolkit().addAWTEventListener(new AWTEventListener() {

            public void eventDispatched(final AWTEvent event) {
                if (event.getID() == KeyEvent.KEY_PRESSED) {
                    System.out.println("Key pressed");
                    final KeyEvent keyEvent = (KeyEvent) event;
                    switch (keyEvent.getKeyCode()) {
                        case KeyEvent.VK_R:
                            System.out.println("Was the r key");
                            if(keyEvent.isControlDown() && keyEvent.isShiftDown()) {
                                System.out.println("HERE");
                            }
                            break;
                    }
                }
            }

        }, AWTEvent.KEY_EVENT_MASK);
        ((JTabbedPane) BurpGuiControl.getRootPane()).getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_R,InputEvent.SHIFT_DOWN_MASK | InputEvent.CTRL_DOWN_MASK),"donone");
        ((JTabbedPane) BurpGuiControl.getRootPane()).getActionMap().put("donone", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                System.out.println("DO nothing");

            }
        });
        JPanel combined = new JPanel(new GridBagLayout());
        combined.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_R,InputEvent.SHIFT_DOWN_MASK | InputEvent.CTRL_DOWN_MASK),"repeater");
        combined.getActionMap().put("repeater", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                System.out.println("Pressed");
            }
        });
        JButton searchButton = new JButton("Search");
        JTextField searchBar = new JTextField("Enter query...");
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 1;
        c.weighty = 0.05;
        c.fill = GridBagConstraints.BOTH;
        searchBar.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {
                if (searchBar.getText().equals("Enter query...")) {
                    searchBar.setText("");
                }
            }
            @Override
            public void focusLost(FocusEvent e) {
                if (searchBar.getText().isEmpty()) {
                    searchBar.setText("Enter query...");
                }
            }
        });
        combined.add(searchBar,c);
        searchButton.addActionListener(e -> {
                if(searchButton.getText().equals("Search")) {
                    searchRepeaterTabsForString(searchBar.getText());
                    searchButton.setText("Clear");
                } else {
                    resetRepeaterTabs();
                    searchBar.setText("Enter query...");
                    searchButton.setText("Search");
                }
        });
        c.gridx = 1;
        combined.add(searchButton);
        c.gridy = 1;
        c.gridx = 0;
        c.gridwidth = 2;
        c.weighty = 0.95;
        combined.add(repeaterComponent,c);
        iBurpExtenderCallbacks.customizeUiComponent(combined);
        BurpGuiControl.addBaseBurpComponent("Repeater",combined);
    }

    @Override
    public void extensionUnloaded() {
        BurpGuiControl.replaceBaseBurpComponent("Repeater",this.repeaterComponent);
    }


    /**
     * Walks the GUI tree to get the Textarea of the Repeater Response
     * @return The Textarea of the Repeater Response
     */
    private JTextArea getRepeaterTabResponseTextArea(Container repeaterTab) {
            Container requestResponsePanel = (Container) repeaterTab.getComponent(3);
            Container innerPanel = (Container) requestResponsePanel.getComponent(0);
            Container splitPane = (Container) innerPanel.getComponent(0);
            //BurpGuiControl.printChildrenComponents(splitPane,0,5);
            Container responsePane = (Container) splitPane.getComponent(2);
            Container innerResponsePane = (Container) responsePane.getComponent(1); //dz_
            Container textRegion = (Container) innerResponsePane.getComponent(1); //dzr
            Container textRegionInnerPane = (Container) textRegion.getComponent(0); //dzb
            Container messageArea = (Container) textRegionInnerPane.getComponent(1); //dzr
            Container a = (Container) messageArea.getComponent(0);//dko
            Container b = (Container) a.getComponent(0); //dte
            Container c = (Container) b.getComponent(1); //c_3
            Container d = (Container) c.getComponent(0); //Viewport
            return (JTextArea) d.getComponent(0);

    }

    private void resetRepeaterTabs(){
        JTabbedPane repeaterTabs = ((JTabbedPane)this.repeaterComponent);
        int index = 0;
        for(Component ignored : repeaterTabs.getComponents()) {
            repeaterTabs.setBackgroundAt(index,new Color(0xBBBBBB));
            index++;
        }
    }

    private void searchRepeaterTabsForString(String search) {
        JTabbedPane repeaterTabs = ((JTabbedPane)this.repeaterComponent);
        int index = 0;
        for(Component repeaterTab : repeaterTabs.getComponents()) {
            try {
                JTextArea requestBody = getRepeaterTabResponseTextArea((Container) repeaterTab);
                System.out.println(requestBody.getText() + " : " + requestBody.getText().contains(search));
                if( requestBody.getText().contains(search) ) {
                    System.out.println(repeaterTabs.getComponentAt(index));
                    repeaterTabs.setBackgroundAt(index,new Color(0xff6633));
                }
                index++;
            }catch(ArrayIndexOutOfBoundsException e) {
                System.out.println(e);
            }
        }
    }

}
