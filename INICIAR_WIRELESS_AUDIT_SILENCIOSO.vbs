Option Explicit

Dim shell, fso, baseDir, scriptPath, pythonwPath, command
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

baseDir = fso.GetParentFolderName(WScript.ScriptFullName)
scriptPath = fso.BuildPath(baseDir, "WirelessAuditPro.py")
pythonwPath = shell.ExpandEnvironmentStrings("%WINDIR%\pyw.exe")
If Not fso.FileExists(pythonwPath) Then
    pythonwPath = shell.ExpandEnvironmentStrings("%LOCALAPPDATA%\Programs\Python\Python314\pythonw.exe")
End If
command = """" & pythonwPath & """ """ & scriptPath & """"

' Window style 0 keeps the launcher and every inherited Python console hidden.
shell.CurrentDirectory = baseDir
shell.Run command, 0, False
