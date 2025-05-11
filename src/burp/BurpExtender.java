package burp;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.awt.event.ItemListener;
import javax.swing.event.DocumentListener;
import javax.swing.event.DocumentEvent;
import java.util.Base64;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPanel;
    private JTextArea headersTextArea;
    private JCheckBox inScopeCheckBox;
    private JCheckBox enabledCheckBox;
    private Map<Integer, JCheckBox> toolCheckboxes;
    
    // Profile management components
    private JTextField profileNameField;
    private JComboBox<String> profileSelector;
    private JButton saveProfileButton;
    private JButton deleteProfileButton;
    private String currentProfile = "Default";
    private Set<String> profileList = new LinkedHashSet<>();
    private boolean isLoadingProfile = false;
    
    private static final String PROFILE_LIST_KEY = "headerManager_profileList";
    private static final String LAST_PROFILE_KEY = "headerManager_lastProfile";
    private static final String VERSION = "1.1";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        callbacks.setExtensionName("Header Manager v" + VERSION);
        
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                initializeUI();
                loadProfileList();
                loadLastProfile();
            }
        });

        callbacks.registerHttpListener(this);
    }

    private void initializeUI() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new BorderLayout());

        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));
        
        // Profile management panel
        JPanel profilePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        profilePanel.setBorder(BorderFactory.createTitledBorder("Profile Management"));
        
        JLabel profileLabel = new JLabel("Profile Name:");
        profileNameField = new JTextField(10);
        saveProfileButton = new JButton("Save");
        
        profileSelector = new JComboBox<>();
        profileSelector.setPreferredSize(new Dimension(150, profileSelector.getPreferredSize().height));
        
        deleteProfileButton = new JButton("Delete");
        
        profilePanel.add(profileLabel);
        profilePanel.add(profileNameField);
        profilePanel.add(saveProfileButton);
        profilePanel.add(new JLabel("Load Profile:"));
        profilePanel.add(profileSelector);
        profilePanel.add(deleteProfileButton);
        
        // Version label
        JLabel versionLabel = new JLabel("v" + VERSION);
        versionLabel.setForeground(Color.GRAY);
        profilePanel.add(Box.createHorizontalStrut(10));
        profilePanel.add(versionLabel);
        
        topPanel.add(profilePanel);
        
        // Initialize rest of UI
        JPanel enablePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        enabledCheckBox = new JCheckBox("Enable Extension", false);
        enabledCheckBox.setForeground(Color.RED);
        enablePanel.add(enabledCheckBox);
        
        enabledCheckBox.addItemListener(e -> {
            if (enabledCheckBox.isSelected()) {
                enabledCheckBox.setForeground(new Color(0, 150, 0)); 
            } else {
                enabledCheckBox.setForeground(Color.RED);
            }
            saveCurrentProfile();
        });
        
        topPanel.add(enablePanel);
        
        JPanel scopePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        inScopeCheckBox = new JCheckBox("In Scope Only", true);
        scopePanel.add(inScopeCheckBox);
        inScopeCheckBox.addItemListener(e -> saveCurrentProfile());
        topPanel.add(scopePanel);

        JPanel toolsPanel = new JPanel(new GridLayout(0, 3, 5, 5));
        toolsPanel.setBorder(BorderFactory.createTitledBorder("Burp Tools"));
        
        toolCheckboxes = new HashMap<>();
        addToolCheckbox(toolsPanel, "Proxy", IBurpExtenderCallbacks.TOOL_PROXY);
        addToolCheckbox(toolsPanel, "Repeater", IBurpExtenderCallbacks.TOOL_REPEATER);
        addToolCheckbox(toolsPanel, "Scanner", IBurpExtenderCallbacks.TOOL_SCANNER);
        addToolCheckbox(toolsPanel, "Intruder", IBurpExtenderCallbacks.TOOL_INTRUDER);
        addToolCheckbox(toolsPanel, "Spider", IBurpExtenderCallbacks.TOOL_SPIDER);
        addToolCheckbox(toolsPanel, "Sequencer", IBurpExtenderCallbacks.TOOL_SEQUENCER);
        addToolCheckbox(toolsPanel, "Decoder", IBurpExtenderCallbacks.TOOL_DECODER);
        addToolCheckbox(toolsPanel, "Comparer", IBurpExtenderCallbacks.TOOL_COMPARER);
        addToolCheckbox(toolsPanel, "Extender", IBurpExtenderCallbacks.TOOL_EXTENDER);
        addToolCheckbox(toolsPanel, "Target", IBurpExtenderCallbacks.TOOL_TARGET);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton selectAllButton = new JButton("Select All");
        JButton deselectAllButton = new JButton("Deselect All");
        
        selectAllButton.addActionListener(e -> {
            setAllToolsSelection(true);
            saveCurrentProfile();
        });
        deselectAllButton.addActionListener(e -> {
            setAllToolsSelection(false);
            saveCurrentProfile();
        });
        
        buttonPanel.add(selectAllButton);
        buttonPanel.add(deselectAllButton);

        topPanel.add(toolsPanel);
        topPanel.add(buttonPanel);
        mainPanel.add(topPanel, BorderLayout.NORTH);

        JPanel headersPanel = new JPanel(new BorderLayout());
        headersPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        headersTextArea = new JTextArea(15, 50);
        headersTextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(headersTextArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createCompoundBorder(
                BorderFactory.createEmptyBorder(5, 0, 5, 0),
                BorderFactory.createTitledBorder("Custom Headers (One per line, format: Header-Name: Header-Value)")
            )
        ));

        String exampleHeaders = "";
        headersTextArea.setText(exampleHeaders);
        
        // Add document listener for headers text area
        headersTextArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                saveCurrentProfile();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                saveCurrentProfile();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                saveCurrentProfile();
            }
        });
        
        headersPanel.add(scrollPane, BorderLayout.CENTER);
        mainPanel.add(headersPanel, BorderLayout.CENTER);

        JPanel statusPanel = new JPanel(new BorderLayout());
        JLabel statusLabel = new JLabel("Ready to process headers");
        statusPanel.add(statusLabel, BorderLayout.WEST);
        mainPanel.add(statusPanel, BorderLayout.SOUTH);

        // Profil yönetimi için olay dinleyicileri ekle
        saveProfileButton.addActionListener(e -> saveProfile());
        profileSelector.addActionListener(e -> {
            if (!isLoadingProfile && profileSelector.getSelectedItem() != null) {
                currentProfile = profileSelector.getSelectedItem().toString();
                loadProfile(currentProfile);
                callbacks.saveExtensionSetting(LAST_PROFILE_KEY, currentProfile);
            }
        });
        deleteProfileButton.addActionListener(e -> deleteCurrentProfile());

        callbacks.customizeUiComponent(mainPanel);
        callbacks.addSuiteTab(this);
    }

    private void addToolCheckbox(JPanel panel, String name, int toolFlag) {
        JCheckBox checkbox = new JCheckBox(name, true);
        checkbox.addItemListener(e -> saveCurrentProfile());
        toolCheckboxes.put(toolFlag, checkbox);
        panel.add(checkbox);
    }

    private void setAllToolsSelection(boolean selected) {
        for (JCheckBox checkbox : toolCheckboxes.values()) {
            checkbox.setSelected(selected);
        }
    }

    @Override
    public String getTabCaption() {
        return "Header Manager";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        
        if (!enabledCheckBox.isSelected()) return;
        
        if (!messageIsRequest) return;

        JCheckBox toolCheckbox = toolCheckboxes.get(toolFlag);
        if (toolCheckbox == null || !toolCheckbox.isSelected()) return;

        if (inScopeCheckBox.isSelected() && !callbacks.isInScope(helpers.analyzeRequest(messageInfo).getUrl())) return;

        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            List<String> headers = new ArrayList<>(requestInfo.getHeaders());
            byte[] request = messageInfo.getRequest();
            String headersText = headersTextArea.getText();

            boolean headersModified = false;
            for (String line : headersText.split("\\n")) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                if (!line.contains(":")) continue;

                String[] parts = line.split(":", 2);
                String headerName = parts[0].trim();
                String headerValue = parts[1].trim();

                boolean headerFound = false;
                for (int i = 0; i < headers.size(); i++) {
                    if (headers.get(i).toLowerCase().startsWith(headerName.toLowerCase() + ":")) {
                        headers.set(i, headerName + ": " + headerValue);
                        headerFound = true;
                        headersModified = true;
                        break;
                    }
                }

                if (!headerFound) {
                    headers.add(headerName + ": " + headerValue);
                    headersModified = true;
                }
            }

            if (headersModified) {
                byte[] body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
                byte[] newRequest = helpers.buildHttpMessage(headers, body);
                messageInfo.setRequest(newRequest);
            }
        } catch (Exception e) {
            callbacks.printError("Error processing headers: " + e.getMessage());
        }
    }
    
    // Profile management methods
    
    private void saveProfile() {
        String profileName = profileNameField.getText().trim();
        if (profileName.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "Please enter a profile name", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        currentProfile = profileName;
        saveCurrentProfile();
        
        // Update profile list
        profileList.add(currentProfile);
        saveProfileList();
        
        // Update profile selector and keep current selection
        isLoadingProfile = true;
        updateProfileSelector();
        profileSelector.setSelectedItem(currentProfile);
        isLoadingProfile = false;
        
        // Save as last used profile
        callbacks.saveExtensionSetting(LAST_PROFILE_KEY, currentProfile);
        
        JOptionPane.showMessageDialog(mainPanel, "Profile saved successfully", "Success", JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void saveCurrentProfile() {
        if (isLoadingProfile || callbacks == null) return;
        
        try {
            StringBuilder settingsBuilder = new StringBuilder();
            
            // Save enabled state
            settingsBuilder.append("enabled=").append(enabledCheckBox.isSelected()).append("\n");
            
            // Save in scope only state
            settingsBuilder.append("inScopeOnly=").append(inScopeCheckBox.isSelected()).append("\n");
            
            // Save tool selections
            for (Map.Entry<Integer, JCheckBox> entry : toolCheckboxes.entrySet()) {
                settingsBuilder.append("tool_").append(entry.getKey()).append("=")
                    .append(entry.getValue().isSelected()).append("\n");
            }
            
            // Save headers - Base64 encode to handle newlines and special characters
            String encodedHeaders = Base64.getEncoder().encodeToString(
                headersTextArea.getText().getBytes("UTF-8"));
            settingsBuilder.append("headers=").append(encodedHeaders);
            
            // Save to extension settings
            callbacks.saveExtensionSetting("headerManager_profile_" + currentProfile, 
                settingsBuilder.toString());
            
        } catch (Exception e) {
            callbacks.printError("Error saving profile: " + e.getMessage());
        }
    }
    
    private void loadProfile(String profileName) {
        isLoadingProfile = true;
        try {
            String settingsStr = callbacks.loadExtensionSetting("headerManager_profile_" + profileName);
            
            if (settingsStr != null && !settingsStr.isEmpty()) {
                Map<String, String> settings = new HashMap<>();
                
                // Parse settings
                for (String line : settingsStr.split("\\n")) {
                    if (line.contains("=")) {
                        String[] parts = line.split("=", 2);
                        settings.put(parts[0], parts[1]);
                    }
                }
                
                // Load enabled state
                if (settings.containsKey("enabled")) {
                    enabledCheckBox.setSelected(Boolean.parseBoolean(settings.get("enabled")));
                }
                
                // Load in scope only state
                if (settings.containsKey("inScopeOnly")) {
                    inScopeCheckBox.setSelected(Boolean.parseBoolean(settings.get("inScopeOnly")));
                }
                
                // Load tool selections
                for (Map.Entry<Integer, JCheckBox> entry : toolCheckboxes.entrySet()) {
                    String key = "tool_" + entry.getKey();
                    if (settings.containsKey(key)) {
                        entry.getValue().setSelected(Boolean.parseBoolean(settings.get(key)));
                    }
                }
                
                // Load headers
                if (settings.containsKey("headers")) {
                    try {
                        byte[] decodedBytes = Base64.getDecoder().decode(settings.get("headers"));
                        headersTextArea.setText(new String(decodedBytes, "UTF-8"));
                    } catch (Exception e) {
                        callbacks.printError("Error decoding headers: " + e.getMessage());
                    }
                }
            }
            
            profileNameField.setText(profileName);
            
        } catch (Exception e) {
            callbacks.printError("Error loading profile: " + e.getMessage());
        } finally {
            isLoadingProfile = false;
        }
    }
    
    private void deleteCurrentProfile() {
        if (profileSelector.getItemCount() <= 1) {
            JOptionPane.showMessageDialog(mainPanel, "Cannot delete the last profile", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        String profileToDelete = profileSelector.getSelectedItem().toString();
        
        int confirm = JOptionPane.showConfirmDialog(
            mainPanel,
            "Are you sure you want to delete the profile \"" + profileToDelete + "\"?",
            "Delete Confirmation",
            JOptionPane.YES_NO_OPTION
        );
        
        if (confirm == JOptionPane.YES_OPTION) {
            // Remove from profile list
            profileList.remove(profileToDelete);
            
            // Delete settings
            callbacks.saveExtensionSetting("headerManager_profile_" + profileToDelete, null);
            
            // Update profile selector
            saveProfileList();
            updateProfileSelector();
            
            // Load first available profile
            if (profileSelector.getItemCount() > 0) {
                String newProfile = profileSelector.getItemAt(0);
                currentProfile = newProfile;
                profileSelector.setSelectedItem(newProfile);
                loadProfile(newProfile);
                callbacks.saveExtensionSetting(LAST_PROFILE_KEY, newProfile);
            }
        }
    }
    
    private void loadProfileList() {
        String profileListStr = callbacks.loadExtensionSetting(PROFILE_LIST_KEY);
        
        if (profileListStr != null && !profileListStr.isEmpty()) {
            String[] profiles = profileListStr.split(",");
            profileList.clear();
            
            for (String profile : profiles) {
                profileList.add(profile);
            }
        }
        
        if (profileList.isEmpty()) {
            // Add default profile if list is empty
            profileList.add("Default");
        }
        
        updateProfileSelector();
    }
    
    private void saveProfileList() {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        
        for (String profile : profileList) {
            if (!first) {
                sb.append(",");
            }
            sb.append(profile);
            first = false;
        }
        
        callbacks.saveExtensionSetting(PROFILE_LIST_KEY, sb.toString());
    }
    
    private void updateProfileSelector() {
        String currentSelection = (String) profileSelector.getSelectedItem();
        
        profileSelector.removeAllItems();
        List<String> sortedProfiles = new ArrayList<>(profileList);
        java.util.Collections.sort(sortedProfiles);
        
        for (String profile : sortedProfiles) {
            profileSelector.addItem(profile);
        }
        
        // Keep the current selection if it still exists
        if (currentSelection != null && profileList.contains(currentSelection)) {
            profileSelector.setSelectedItem(currentSelection);
        }
    }
    
    private void loadLastProfile() {
        String lastProfile = callbacks.loadExtensionSetting(LAST_PROFILE_KEY);
        
        if (lastProfile != null && !lastProfile.isEmpty() && profileList.contains(lastProfile)) {
            currentProfile = lastProfile;
            profileSelector.setSelectedItem(currentProfile);
        } else if (profileSelector.getItemCount() > 0) {
            currentProfile = profileSelector.getItemAt(0).toString();
            profileSelector.setSelectedItem(currentProfile);
        }
        
        loadProfile(currentProfile);
    }
}
