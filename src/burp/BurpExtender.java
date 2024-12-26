package burp;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPanel;
    private JTextArea headersTextArea;
    private JCheckBox inScopeCheckBox;
    private JCheckBox enabledCheckBox;
    private Map<Integer, JCheckBox> toolCheckboxes;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        callbacks.setExtensionName("Header Manager");
        
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                initializeUI();
            }
        });

        callbacks.registerHttpListener(this);
    }

    private void initializeUI() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new BorderLayout());

        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));
        
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
        });
        
        topPanel.add(enablePanel);
        
        JPanel scopePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        inScopeCheckBox = new JCheckBox("In Scope Only", true);
        scopePanel.add(inScopeCheckBox);
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
        
        selectAllButton.addActionListener(e -> setAllToolsSelection(true));
        deselectAllButton.addActionListener(e -> setAllToolsSelection(false));
        
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
        
        headersPanel.add(scrollPane, BorderLayout.CENTER);
        mainPanel.add(headersPanel, BorderLayout.CENTER);

        JPanel statusPanel = new JPanel(new BorderLayout());
        JLabel statusLabel = new JLabel("Ready to process headers");
        statusPanel.add(statusLabel, BorderLayout.WEST);
        mainPanel.add(statusPanel, BorderLayout.SOUTH);

        callbacks.customizeUiComponent(mainPanel);
        callbacks.addSuiteTab(this);
    }

    private void addToolCheckbox(JPanel panel, String name, int toolFlag) {
        JCheckBox checkbox = new JCheckBox(name, true);
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
}