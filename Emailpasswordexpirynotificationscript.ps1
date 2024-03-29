# Using Delegated Access
# Connect-MgGraph -Scopes 'User.Read.All', 'Mail.Send', 'Domain.Read.All'

# Use App-only access with a client secret credential.
$ClientSecret = ConvertTo-SecureString '9WV8Q~Cg46taGwOA2crnhgh_IRUeeh7ee.NH2bRd' -AsPlainText -Force
$ClientSecretCredential = New-Object System.Management.Automation.PSCredential('c42340ce-163d-4512-92d8-b9c4c90914e3', $ClientSecret)
Connect-MgGraph -TenantId 'ca4fd2d7-85ea-42d2-b7b3-30ef2666c7ab' -ClientSecretCredential $ClientSecretCredential

# Define the tenant ID
$tenant_ID = 'ca4fd2d7-85ea-42d2-b7b3-30ef2666c7ab'

# Use App-only access with a certificate
# Connect-MgGraph -ClientId 'c42340ce-163d-4512-92d8-b9c4c90914e3' -TenantId $tenant_ID -CertificateThumbprint '90C86AB1BD3E413E1934555EA3FB33FCAC5A9335'

# Get the context
Get-MgContext

# Fetch domains with non-infinite password validity periods
$domains = Get-MgDomain | Where-Object { $_.PasswordValidityPeriodInDays -ne 2147483647 } | Select-Object Id, PasswordValidityPeriodInDays

# Set default password validity period for domains without specified period
$domains | ForEach-Object { if (!$_.PasswordValidityPeriodInDays) { $_.PasswordValidityPeriodInDays = 90 } }

# Fetch users based on filter and properties
$properties = "UserPrincipalName", "mail", "displayName", "PasswordPolicies", "LastPasswordChangeDateTime", "CreatedDateTime"
$users = Get-MgUser -Filter "userType eq 'member' and accountEnabled eq true" -Property $properties -ConsistencyLevel Eventual -All -PageSize 999 -Verbose

# Define allowed domains
$allowedDomains = @('aacn.org') # Replace with your actual domain values

# Filter users based on additional conditions
$filteredUsers = $users | Where-Object {
    $_.PasswordPolicies -ne 'DisablePasswordExpiration' -and $($_.UserPrincipalName.Split('@')[1]) -in $allowedDomains
}

# Add additional properties to user objects
$users | Add-Member -MemberType NoteProperty -Name Domain -Value $null 
$users | Add-Member -MemberType NoteProperty -Name MaxPasswordAge -Value 0 
$users | Add-Member -MemberType NoteProperty -Name PasswordAge -Value 0 
$users | Add-Member -MemberType NoteProperty -Name ExpiresOn -Value (Get-Date '1970-01-01') 
$users | Add-Member -MemberType NoteProperty -Name DaysRemaining -Value 0

# Calculate password expiration details for users
$timeNow = Get-Date
foreach ($user in $users) { 
    $userDomain = ($user.userPrincipalName).Split('@')[1] 
    $maxPasswordAge = ($domains | Where-Object { $_.id -eq $userDomain }).PasswordValidityPeriodInDays

    if ($maxPasswordAge -eq 2147483647) { 
        continue; 
    }

    $passwordAge = (New-TimeSpan -Start $user.LastPasswordChangeDateTime -End $timeNow).Days 
    $expiresOn = (Get-Date $user.LastPasswordChangeDateTime).AddDays($maxPasswordAge) 

    $user.Domain = $userDomain 
    $user.MaxPasswordAge = $maxPasswordAge 
    $user.PasswordAge = $passwordAge 
    $user.ExpiresOn = $expiresOn 
    $user.DaysRemaining = if (($daysRemaining = (New-TimeSpan -Start $timeNow -End $expiresOn).Days) -lt 1) { 0 } else { $daysRemaining } 
}

# Sort users by days remaining and display details
$users | Sort-Object DaysRemaining | Format-Table UserPrincipalName, DisplayName, Mail, PasswordAge, ExpiresOn, DaysRemaining

## Specify which days remaining will be notified. 
$PasswordNotificationWindowInDays = @(47)
#---
 
# Path to the AACN logo image
$logoPath = "./aacnlogo.png"
 
# Load Logo and encode as base64 string
$logo = [Convert]::ToBase64String((Get-Content $logoPath -Encoding Byte))
 
 
# Specify the sender's email address. 
$SenderEmailAddress = 'reset-password@aacn.org'

# Send Office 365 password expiration notification 
foreach ($user in $users) { 
# Guard clause if the user's DaysRemaining value is not within - 
# the $PasswordNotificationWindowInDays 
# and has no email address (can't send the user an email) 
if ($user.DaysRemaining -notin $PasswordNotificationWindowInDays -or !$user.Mail) { 
continue; 
}
# Compose the message 
$mailBody = @() 
$mailBody += '<!DOCTYPE html><html><body>' 
# Add Logo
$mailBody += "<img src='data:image/png;base64,${logo}'>"
 
$mailBody += "<p>Dear, $($user.DisplayName)</p>" 
$mailBody += "<p>AACN password for ($($user.UserPrincipalName)) will expire on <b>$(get-date $user.ExpiresOn -Format D)</b>." 
$mailBody += "<br>Please change your password by going to the following links:Password reset link
OR your profile page at: https://myaccount.microsoft.com
As always, if you need support, feel free to reach out to us at 570@aacn.org..</p>" 
$mailBody += "<p>Thank you. 
AACN IT Team</p>"
# # Create the mail object 
# $mailObject = @{ 
# Message = @{ 
# ToRecipients = @( 
# @{ 
# EmailAddress = @{ 
# Address = $($user.Mail) 
# } 
# } 
# ) 
# Subject = "Your AACN password will expire soon" 
# Body = @{ 
# ContentType = "HTML" 
# Content = ($mailBody -join "`n") 
# } 
# } 
# SaveToSentItems = "false" 
# }
# # Send the Office 365 Password Expiration Notification Email 
# try { 
# "Sending password expiration notice to [$($user.displayName)] [Expires in: $($user.daysRemaining) days] [Expires on: $($user.expiresOn)]" | Out-Default 
# Send-MgUserMail -BodyParameter $mailObject -UserId $SenderEmailAddress 
# } 
# catch { 
# "There was an error sending the notification to $($user.displayName)" | Out-Default 
# $_.Exception.Message | Out-Default 
# } 
# }

# Google email credentials
$googleEmail = "reset-password@aacn.org"
$googlePassword = ConvertTo-SecureString "@Aacn92656@%" -AsPlainText -Force

# Create the credentials object
# $credentials = New-Object System.Net.NetworkCredential($googleEmail, $googlePassword)
$credentials = New-Object System.Management.Automation.PSCredential($googleEmail, $googlePassword)

# Compose the email message
$mailParams = @{
    From       = $googleEmail
    To         = $user.Mail
    Subject    = "Your AACN password will expire soon"
    Body       = $mailBody -join "`n"
    BodyAsHtml = $true
    SmtpServer = "smtp.gmail.com"
    Port       = 587
    Credential = $credentials
    UseSsl     = $true
}

try {
    "Sending password expiration notice to [$($user.displayName)] [Expires in: $($user.daysRemaining) days] [Expires on: $($user.expiresOn)]" | Out-Default
    Send-MailMessage @mailParams
}
catch {
    "There was an error sending the notification to $($user.displayName)" | Out-Default
    $_.Exception.Message | Out-Default
}
}
