@{
    RootModule = 'DRAC.psm1'
    ModuleVersion = '1.0.1'
    GUID = '679ffa5a-9451-3dc1-9529-8689cbb0c8a0'
    Author = 'Alexey Miasoedov'
    CompanyName = 'MyCompany'
    Copyright = '(c) 2016 Alexey Miasoedov. All rights reserved.'
    Description = 'Interact with DRAC via CIM interface'
    PowerShellVersion = '4.0'
    # PowerShellHostName = ''
    # PowerShellHostVersion = ''
    # DotNetFrameworkVersion = ''
    # CLRVersion = ''
    # ProcessorArchitecture = ''
    # RequiredModules = @()
    # RequiredAssemblies = @()
    # ScriptsToProcess = @('load\load-dependencies.ps1')
    # TypesToProcess = @()
    # FormatsToProcess = @()
    # NestedModules = @()
    FunctionsToExport = #'*-*' # only Verb-Noun; avoid helper functions
        'BootTo-Device',
        #'Discover-',
        'Dismount-Image',
        'Get-FcWwn',
        'Get-FwInfo',
        'Get-Job',
        'Get-SEL',
        'Get-SystemInfo',
        'Invoke-CIM',
        'Mount-Image',
        'Reboot-Device',
        'Set-EmbeddedNic',
        'Set-TpmModule',
        'Update-Fw'
    CmdletsToExport = '*'
    VariablesToExport = '*'
    AliasesToExport = '*'
    # ModuleList = @()
    FileList = 'DRAC.psm1'
    # PrivateData = @{
    #   'RequiredPackages' = @()
    # }
    # HelpInfoURI = ''
    DefaultCommandPrefix = 'Drac'
}