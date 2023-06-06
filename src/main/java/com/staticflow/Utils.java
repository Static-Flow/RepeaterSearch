package com.staticflow;

import main.java.com.staticflow.BurpGuiControl;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class which contains the various functionality for this extension
 */
public class Utils {

    private static final String SEARCH = "Search";
    private static final String RESET = "Reset";
    private static final String ENTER_QUERY = "Enter query...";
    private static boolean searchResponseForText = false;
    private static boolean searchRequestForText = true;
    private static boolean useRegex = false;

    private Utils() {}

    /**
     * Called by {@link RepeaterSearch#extensionUnloaded()} it first resets the color on any repeater tabs, removes the custom search bar from the Repeater
     * tab component, then repaints the Repeater tab component
     */
    public static void cleanUpExtension() {
        resetRepeaterTabs();
        Component repeaterComponent = ExtensionState.getInstance().getRepeaterComponent();
        ((Container)repeaterComponent).remove(0);
        repeaterComponent.revalidate();
        repeaterComponent.repaint();
    }

    /**
     * This method, called during Extension initialization at {@link RepeaterSearch#initialize} injects the custom search bar into the Repeater tab component
     * using the following steps:
     * <br>
     *      1. Obtain references to the Repeater tab Component and its inner JTabbedPane from {@link ExtensionState}<br>
     *      2. Change the Swing Layout of the Repeater tab Component to {@link GridBagLayout}<br>
     *      3. Remove the JTabbedPane from the Swing Tree of the Repeater tab Component<br>
     *      4. Create the custom search bar component using {@link Utils#generateSearchBar()}<br>
     *      5. Insert the custom search bar into the Repeater tab Component using the configured {@link GridBagConstraints} and set it to visible<br>
     *      6. Re-insert the JTabbedPane into the Repeater tab Component using the configured {@link GridBagConstraints} and set it to visible<br>
     *      7. Revalidate/Repaint the Repeater tab Component
     */
    public static void addSearchBarToRepeaterTab() {
        Component repeaterComponent = ExtensionState.getInstance().getRepeaterComponent();
        JTabbedPane repeaterTabbedPane = ExtensionState.getInstance().getRepeaterTabbedPane();

        ((Container) repeaterComponent).setLayout(new GridBagLayout());
        ((Container) repeaterComponent).remove(repeaterTabbedPane);
        Component customRepeaterComponent = generateSearchBar();

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weighty = 0.01;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.BOTH;
        ((Container) repeaterComponent).add(customRepeaterComponent,gbc);
        customRepeaterComponent.setVisible(true);
        GridBagConstraints constraints = ((GridBagLayout) ((Container) repeaterComponent).getLayout()).getConstraints(repeaterTabbedPane);
        constraints.gridx = 0;
        constraints.gridy = 1;
        constraints.weighty = 1;
        constraints.weightx = 1;
        constraints.anchor = GridBagConstraints.NORTH;
        constraints.fill = GridBagConstraints.BOTH;
        ((Container) repeaterComponent).add(repeaterTabbedPane,constraints);
        repeaterTabbedPane.setVisible(true);
        repeaterComponent.revalidate();
        repeaterComponent.repaint();
    }

    /**
     * This method creates the custom search bar used by this extension. It comprises a JTextField for the search query, a JButton for executing the search,
     * and 3 JCheckboxes which configure the different search modes which include: <br>
     * 1. Searching the Request body<br>
     * 2. Searching the Response body<br>
     * 3. Interpreting the search query as a regular expression<br>
     * Any combination of the 3 may be used to facilitate different search requirements.
     * @return The custom search bar Component
     */
    private static Component generateSearchBar() {
        //HIGH LEVEL COMPONENTS,CONTAINERS, AND LAYOUT MANAGERS
        Container customRepeaterComponent = new JPanel(new GridBagLayout());
        JPanel searchBarPanel = new JPanel(new GridBagLayout());
        JPanel searchBarButtonsPanel = new JPanel();
        searchBarButtonsPanel.setLayout(new BoxLayout(searchBarButtonsPanel,
                BoxLayout.X_AXIS));
        JButton searchButton = new JButton(SEARCH);
        JButton resetButton = new JButton(RESET);
        JTextField searchBar = new JTextField(ENTER_QUERY);
        GridBagConstraints c = new GridBagConstraints();

        //BUILD SEARCH BAR
        /*
         * This listener is purely for a nicer user experience. When clicking into the search bar, the default text is highlighted for easy replacement
         */
        searchBar.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {
                if(searchBar.getText().equals(ENTER_QUERY)) {
                    searchBar.selectAll();
                }
            }

            @Override
            public void focusLost(FocusEvent e) {
                //UnNeeded
            }
        });
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1;
        gbc.weighty = 1;
        searchBarPanel.add(searchBar,gbc);

        //BUILD SEARCH SUBMIT AND FILTER COMPONENTS
        searchButton.addActionListener(e -> searchRepeaterTabsForString(searchBar.getText()));
        searchBarButtonsPanel.add(searchButton);
        resetButton.addActionListener(e -> resetRepeaterTabs());
        searchBarButtonsPanel.add(resetButton);
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

        //INSERT SEARCH BAR AND BUTTON PANEL TO MAIN COMPONENT
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 0.90;
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;
        customRepeaterComponent.add(searchBarPanel,c);
        c.gridx = 1;
        c.weightx = 0.10;
        customRepeaterComponent.add(searchBarButtonsPanel,c);
        return customRepeaterComponent;
    }

    /**
     * This method loops over every Repeater Tab and uses {@link BurpGuiControl#findAllComponentsOfType} to obtain references to the Request/Response JTextAreas
     * and depending on the users search filter options passes either one or both of them to {@link Utils#searchTextArea} to determine if they contain the users
     * search query. If either return True, the Repeater Tab's color is changed to indicate a match.
     * @param search The string to use for searching. Can either be a plain string or a Regular Expression
     */
    private static void searchRepeaterTabsForString(String search) {
        JTabbedPane repeaterTabs = ExtensionState.getInstance().getRepeaterTabbedPane();
        ExtensionState.getInstance().getCallbacks().logging().logToOutput("Searching for: "+search);
        for( int i=0; i < repeaterTabs.getTabCount(); i++) {
            try{
                repeaterTabs.setBackgroundAt(i,new Color(0xBBBBBB));
                List<Component> repeaterTabRequestResponseJTextAreas = BurpGuiControl.findAllComponentsOfType((Container) repeaterTabs.getComponentAt(i), JTextArea.class);

                if ( searchRequestForText ) {
                    JTextArea requestTextArea = (JTextArea) repeaterTabRequestResponseJTextAreas.get(0);
                    ExtensionState.getInstance().getCallbacks().logging().logToOutput(requestTextArea.getText());
                    if (searchTextArea(search,requestTextArea) ) {
                        repeaterTabs.setBackgroundAt(i,new Color(0xff6633));
                    }
                }
                if ( searchResponseForText ) {
                    JTextArea responseTextArea = (JTextArea) repeaterTabRequestResponseJTextAreas.get(1);
                    ExtensionState.getInstance().getCallbacks().logging().logToOutput(responseTextArea.getText());
                    if (searchTextArea(search, responseTextArea)) {
                        repeaterTabs.setBackgroundAt(i,new Color(0xff6633));
                    }
                }
            }catch(Exception e){
                ExtensionState.getInstance().getCallbacks().logging().logToOutput(e.getMessage());
            }
        }
    }

    /**
     * This method loops over every repeater tab and resets it's tab color to prepare for a new search or when the extension is being unloaded
     */
    private static void resetRepeaterTabs(){
        JTabbedPane repeaterTabs = ExtensionState.getInstance().getRepeaterTabbedPane();
        for(int i=0; i < repeaterTabs.getTabCount(); i++) {
            repeaterTabs.setBackgroundAt(i,new Color(0x000000));
        }
    }

    /**
     * This method performs the actual search over a Request/Response JTextArea for the search string. It either uses the {@link String#contains} method in the
     * case of a simple string, or uses the {@link Pattern} and {@link Matcher} for a Regular Expression string.
     * @param search The string to use for searching. Can either be a plain string or a Regular Expression
     * @param textArea The Request/Response JTextArea from a Repeater Tab
     * @return True if the JTextArea contains the simple string or the Regular Expression found a Match, False otherwise
     */
    private static boolean searchTextArea(String search, JTextArea textArea) {
        if (useRegex) {
            Pattern pattern = Pattern.compile(search,Pattern.MULTILINE);
            Matcher matcher = pattern.matcher(textArea.getText());
            return matcher.find();
        } else {
            return textArea.getText().contains(search);
        }
    }


}
