package com.staticflow;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RepeaterSearch implements IBurpExtender, IExtensionStateListener {

    public static final String REPEATER = "Repeater";
    public static final String SEARCH = "Search";
    public static final String ENTER_QUERY = "Enter query...";
    private Component repeaterComponent;
    private IBurpExtenderCallbacks callbacks;
    private boolean searchResponseForText;
    private boolean searchRequestForText;
    private boolean useRegex;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.searchRequestForText = true;
        this.callbacks = iBurpExtenderCallbacks;
        iBurpExtenderCallbacks.registerExtensionStateListener(this);
        this.repeaterComponent = BurpGuiControl.getBaseBurpComponent(REPEATER);
        JPanel combined = new JPanel(new GridBagLayout());
        JPanel searchBarPanel = new JPanel(new GridBagLayout());
        JPanel searchBarButtonsPanel = new JPanel();
        searchBarButtonsPanel.setLayout(new BoxLayout(searchBarButtonsPanel,
                BoxLayout.Y_AXIS));
        JButton searchButton = new JButton(SEARCH);
        JTextField searchBar = new JTextField(ENTER_QUERY);
        GridBagConstraints c = new GridBagConstraints();
        GridBagConstraints gbc = new GridBagConstraints();

        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 0.90;
        c.weighty = 0.05;
        c.fill = GridBagConstraints.BOTH;
        searchBar.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (searchBar.getText().equals(ENTER_QUERY)) {
                    searchBar.setText("");
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {

            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {
                if (searchBar.getText().isEmpty()) {
                    searchBar.setText(ENTER_QUERY);
                }
            }
        });
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1;
        gbc.weighty = 0.50;
        searchBarPanel.add(searchBar,gbc);
        searchBar.addKeyListener(new KeyListener() {
            @Override
            public void keyTyped(KeyEvent e) {
                searchButton.setText(SEARCH);
                resetRepeaterTabs();
            }

            @Override
            public void keyPressed(KeyEvent e) {

            }

            @Override
            public void keyReleased(KeyEvent e) {

            }
        });
        searchButton.addActionListener(e -> {
                if(searchButton.getText().equals(SEARCH)) {
                    searchRepeaterTabsForString(searchBar.getText());
                    searchButton.setText("Clear");
                } else {
                    resetRepeaterTabs();
                    searchBar.setText(ENTER_QUERY);
                    searchButton.setText(SEARCH);
                    resetRepeaterTabs();
                }
        });
        searchBarButtonsPanel.add(searchButton);
        JCheckBox searchRequest = new JCheckBox("Request");
        searchRequest.setSelected(true);
        searchRequest.addChangeListener(e -> searchRequestForText = !searchRequestForText);
        searchBarButtonsPanel.add(searchRequest);
        JCheckBox searchResponse = new JCheckBox("Response");
        searchResponse.addChangeListener(e -> searchResponseForText = !searchResponseForText);
        searchBarButtonsPanel.add(searchResponse);
        JCheckBox searchRegex = new JCheckBox("Regex");
        searchRegex.addChangeListener(e -> useRegex = !useRegex);
        searchBarButtonsPanel.add(searchRegex);
        combined.add(searchBarPanel,c);
        c.gridx = 1;
        c.weightx = 0.10;
        combined.add(searchBarButtonsPanel,c);
        c.gridy = 1;
        c.gridx = 0;
        c.gridwidth = 2;
        c.weighty = 0.95;
        combined.add(repeaterComponent,c);
        iBurpExtenderCallbacks.customizeUiComponent(combined);
        BurpGuiControl.addBaseBurpComponent(REPEATER,combined);
    }

    @Override
    public void extensionUnloaded() {
        resetRepeaterTabs();
        BurpGuiControl.replaceBaseBurpComponent(REPEATER,this.repeaterComponent);
    }

    private void resetRepeaterTabs(){
        JTabbedPane repeaterTabs = ((JTabbedPane)this.repeaterComponent);
        for(int i=0; i < repeaterTabs.getTabCount()-1; i++) {
            repeaterTabs.setBackgroundAt(i,new Color(0xBBBBBB));

        }
    }

    private void searchRepeaterTabsForString(String search) {
        JTabbedPane repeaterTabs = ((JTabbedPane)this.repeaterComponent);
        for( int i=0; i < repeaterTabs.getTabCount()-1; i++) {
            try {
                if ( searchRequestForText ) {
                    System.out.println("Searching request");
                    JTextArea requestTextArea =
                            BurpGuiControl.getRepeaterTabRequestTextArea((Container) repeaterTabs.getComponentAt(i));
                    if (searchTextArea(search,requestTextArea) ) {
                        System.out.println("Found in request");
                        repeaterTabs.setBackgroundAt(i,new Color(0xff6633));
                    }
                } else if ( searchResponseForText ) {
                    System.out.println("Searching response");
                    JTextArea responseTextArea =
                            BurpGuiControl.getRepeaterTabResponseTextArea((Container) repeaterTabs.getComponentAt(i));
                    if (searchTextArea(search, responseTextArea)) {
                        System.out.println("Found in response");
                        repeaterTabs.setBackgroundAt(i,new Color(0xff6633));
                    }
                }
            }catch(ArrayIndexOutOfBoundsException e) {
                this.callbacks.printError(e.getMessage());
            }
        }
    }

    private boolean searchTextArea(String search, JTextArea textArea) {
        if (useRegex) {
            System.out.println("Using regex");
            Pattern pattern = Pattern.compile(search,Pattern.MULTILINE);
            Matcher matcher = pattern.matcher(textArea.getText());
            return matcher.find();
        } else {
            System.out.println("Using string matching");
            return textArea.getText().contains(search);
        }
    }

}
