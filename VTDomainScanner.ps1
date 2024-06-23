Add-Type -AssemblyName System.Windows.Forms

# Function to create the GUI
function Show-GUI {
    [void] [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
    [void] [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "VirusTotal Domain Scanner"
    $form.Size = New-Object System.Drawing.Size(500,400)
    $form.StartPosition = "CenterScreen"
    $form.AutoSize = $true
    $form.AutoSizeMode = "GrowAndShrink"

    $apiLabel = New-Object System.Windows.Forms.Label
    $apiLabel.Text = "API Key:"
    $apiLabel.Location = New-Object System.Drawing.Point(10,20)
    $apiLabel.AutoSize = $true
    $form.Controls.Add($apiLabel)

    $apiKeyBox = New-Object System.Windows.Forms.TextBox
    $apiKeyBox.Location = New-Object System.Drawing.Point(100,20)
    $apiKeyBox.Size = New-Object System.Drawing.Size(350,20)
    $form.Controls.Add($apiKeyBox)

    $inputLabel = New-Object System.Windows.Forms.Label
    $inputLabel.Text = "Input CSV Path:"
    $inputLabel.Location = New-Object System.Drawing.Point(10,60)
    $inputLabel.AutoSize = $true
    $form.Controls.Add($inputLabel)

    $inputBox = New-Object System.Windows.Forms.TextBox
    $inputBox.Location = New-Object System.Drawing.Point(100,60)
    $inputBox.Size = New-Object System.Drawing.Size(250,20)
    $form.Controls.Add($inputBox)

    $inputButton = New-Object System.Windows.Forms.Button
    $inputButton.Text = "Browse"
    $inputButton.Location = New-Object System.Drawing.Point(360,60)
    $inputButton.Size = New-Object System.Drawing.Size(75,23)
    $inputButton.Add_Click({
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openFileDialog.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
        $openFileDialog.ShowDialog() | Out-Null
        $inputBox.Text = $openFileDialog.FileName
    })
    $form.Controls.Add($inputButton)

    $outputLabel = New-Object System.Windows.Forms.Label
    $outputLabel.Text = "Output CSV Path:"
    $outputLabel.Location = New-Object System.Drawing.Point(10,100)
    $outputLabel.AutoSize = $true
    $form.Controls.Add($outputLabel)

    $outputBox = New-Object System.Windows.Forms.TextBox
    $outputBox.Location = New-Object System.Drawing.Point(100,100)
    $outputBox.Size = New-Object System.Drawing.Size(250,20)
    $form.Controls.Add($outputBox)

    $outputButton = New-Object System.Windows.Forms.Button
    $outputButton.Text = "Browse"
    $outputButton.Location = New-Object System.Drawing.Point(360,100)
    $outputButton.Size = New-Object System.Drawing.Size(75,23)
    $outputButton.Add_Click({
        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
        $saveFileDialog.ShowDialog() | Out-Null
        $outputBox.Text = $saveFileDialog.FileName
    })
    $form.Controls.Add($outputButton)

    $modeLabel = New-Object System.Windows.Forms.Label
    $modeLabel.Text = "Mode:"
    $modeLabel.Location = New-Object System.Drawing.Point(10,140)
    $modeLabel.AutoSize = $true
    $form.Controls.Add($modeLabel)

    $modeComboBox = New-Object System.Windows.Forms.ComboBox
    $modeComboBox.Location = New-Object System.Drawing.Point(100,140)
    $modeComboBox.Size = New-Object System.Drawing.Size(100,20)
    $modeComboBox.Items.AddRange(@("Light", "Dark"))
    $modeComboBox.SelectedIndex = 0
    $form.Controls.Add($modeComboBox)
    $modeComboBox.add_SelectedIndexChanged({
        Set-Theme -form $form -mode $modeComboBox.SelectedItem
    })

    $progressBar = New-Object System.Windows.Forms.ProgressBar
    $progressBar.Location = New-Object System.Drawing.Point(10,180)
    $progressBar.Size = New-Object System.Drawing.Size(450,23)
    $progressBar.Style = "Continuous"
    $form.Controls.Add($progressBar)

    $progressMessage = New-Object System.Windows.Forms.Label
    $progressMessage.Text = "Let's get started!"
    $progressMessage.Location = New-Object System.Drawing.Point(10,210)
    $progressMessage.AutoSize = $true
    $form.Controls.Add($progressMessage)

    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Text = "Status: Idle"
    $statusLabel.Location = New-Object System.Drawing.Point(10,240)
    $statusLabel.AutoSize = $true
    $form.Controls.Add($statusLabel)

    $timerLabel = New-Object System.Windows.Forms.Label
    $timerLabel.Text = "Running Time: 00:00:00"
    $timerLabel.Location = New-Object System.Drawing.Point(10,270)
    $timerLabel.AutoSize = $true
    $form.Controls.Add($timerLabel)

    $delayLabel = New-Object System.Windows.Forms.Label
    $delayLabel.Text = "Delay Time: 00:00"
    $delayLabel.Location = New-Object System.Drawing.Point(10,300)
    $delayLabel.AutoSize = $true
    $form.Controls.Add($delayLabel)

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Location = New-Object System.Drawing.Point(100,330)
    $okButton.Size = New-Object System.Drawing.Size(75,23)
    $okButton.Add_Click({
        $apiKey = $apiKeyBox.Text
        $inputPath = $inputBox.Text
        $outputPath = $outputBox.Text
        $mode = $modeComboBox.SelectedItem
        $form.Close()
        Process-CSV -ApiKey $apiKey -InputPath $inputPath -OutputPath $outputPath -Mode $mode -ProgressBar $progressBar -StatusLabel $statusLabel -TimerLabel $timerLabel -DelayLabel $delayLabel -ProgressMessage $progressMessage
    })
    $form.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.Location = New-Object System.Drawing.Point(200,330)
    $cancelButton.Size = New-Object System.Drawing.Size(75,23)
    $cancelButton.Add_Click({ $form.Close() })
    $form.Controls.Add($cancelButton)

    Set-Theme -form $form -mode $modeComboBox.SelectedItem

    $form.ShowDialog()
}

# Function to set the form theme
function Set-Theme {
    param (
        [System.Windows.Forms.Form]$form,
        [string]$mode
    )

    if ($mode -eq "Dark") {
        $form.BackColor = [System.Drawing.Color]::Black
        foreach ($control in $form.Controls) {
            $control.ForeColor = [System.Drawing.Color]::White
            if ($control -is [System.Windows.Forms.TextBox] -or $control -is [System.Windows.Forms.ComboBox]) {
                $control.BackColor = [System.Drawing.Color]::Gray
            }
        }
    } else {
        $form.BackColor = [System.Drawing.Color]::White
        foreach ($control in $form.Controls) {
            $control.ForeColor = [System.Drawing.Color]::Black
            if ($control -is [System.Windows.Forms.TextBox] -or $control -is [System.Windows.Forms.ComboBox]) {
                $control.BackColor = [System.Drawing.Color]::White
            }
        }
    }
}
# Function to process the CSV file
function Process-CSV {
    param (
        [string]$ApiKey,
        [string]$InputPath,
        [string]$OutputPath,
        [string]$Mode,
        [System.Windows.Forms.ProgressBar]$ProgressBar,
        [System.Windows.Forms.Label]$StatusLabel,
        [System.Windows.Forms.Label]$TimerLabel,
        [System.Windows.Forms.Label]$DelayLabel,
        [System.Windows.Forms.Label]$ProgressMessage
    )

    # Set the form theme
    Set-Theme -form $ProgressBar.FindForm() -mode $Mode

    $csvContent = Import-Csv -Path $InputPath -Header "Domain"
    $results = @()
    $totalDomains = $csvContent.Count
    $processedDomains = 0
    $requestCount = 0

    $startTime = [datetime]::Now
    $delayTime = New-TimeSpan -Minutes 1
    $funnyMessages = @("Let's get started!", "Making progress!", "Almost there!", "Keep going!", "Hang tight!")

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 100
0
    $timer.Add_Tick({
        $elapsed = [datetime]::Now - $startTime
        $TimerLabel.Text = "Running Time: " + $elapsed.ToString("hh\:mm\:ss")
    })
    $timer.Start()

    foreach ($row in $csvContent) {
        $domain = $row.Domain
        $url = "https://www.virustotal.com/api/v3/domains/$domain"
        try {
            $headers = @{
                "x-apikey" = $ApiKey
            }
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
            Write-Output "Response for ${domain}: $($response | Out-String)"
            
            if ($response -ne $null) {
                $data = $response.data
                $malicious_vendors = if ($data.attributes.last_analysis_stats.malicious -ne $null) { $data.attributes.last_analysis_stats.malicious } else { 0 }
                $community_score = if ($data.attributes.reputation -ne $null) { $data.attributes.reputation } else { 0 }
                $scan_date = if ($data.attributes.last_analysis_date -ne $null) { 
                    [datetime]::FromFileTime($data.attributes.last_analysis_date * 10000000 + 116444736000000000) 
                } else { "" }
                $creation_date = if ($data.attributes.creation_date -ne $null) { 
                    [datetime]::FromFileTime($data.attributes.creation_date * 10000000 + 116444736000000000) 
                } else { "" }
                $permalink = "https://www.virustotal.com/gui/domain/$domain"
            } else {
                $malicious_vendors = 0
                $community_score = 0
                $scan_date = ""
                $creation_date = ""
                $permalink = ""
            }

            $result = [PSCustomObject]@{
                Resource = $domain
                "Malicious By Vendors" = $malicious_vendors
                CreationDate = $creation_date
                CommunityScore = $community_score
                LastAnalysisDate = $scan_date
                "Analysis Links" = $permalink
            }
            $results += $result
        } catch {
            Write-Output "Error processing ${domain}: $_"
        }

        $processedDomains++
        $requestCount++

        # Update progress bar and status
        $ProgressBar.Value = [math]::Floor(($processedDomains / $totalDomains) * 100)
        $StatusLabel.Text = "Status: Processing $processedDomains of $totalDomains domains"
        $ProgressMessage.Text = $funnyMessages[$processedDomains % $funnyMessages.Count]

        # Check rate limit and sleep if necessary
        if ($requestCount -ge 4) {
            Write-Output "Rate limit reached. Sleeping for 60 seconds."
            $StatusLabel.Text = "Status: Rate limit reached. Sleeping for 60 seconds."
            for ($i = 60; $i -gt 0; $i--) {
                $DelayLabel.Text = "Delay Time: 00:" + "{0:D2}" -f $i
                Start-Sleep -Seconds 1
            }
            $requestCount = 0
        }
    }

    $results | Export-Csv -Path $OutputPath -NoTypeInformation

    # Create explanation of columns
    $explanation = @"
Column Name,Description
Resource,The domain that was scanned
Malicious By Vendors,Number of security vendors that flagged the domain as malicious
CreationDate,The creation date of the domain
CommunityScore,Reputation score from the community
LastAnalysisDate,The date of the last analysis
Analysis Links,Link to the detailed analysis on VirusTotal
"@
    $explanationPath = [System.IO.Path]::ChangeExtension($OutputPath, [System.IO.Path]::GetExtension($OutputPath) + "_explanation.csv")
    $explanation | Out-File -FilePath $explanationPath -Encoding utf8

    Write-Output "Scanning complete. Results saved to $OutputPath"
    $StatusLabel.Text = "Status: Complete. Results saved to $OutputPath"
}

# Run the GUI
Show-GUI
