# Password Extractor

Transfer passwords between browsers. Export your passwords to XML or CSV files to transfer them between browsers. Its XML import/export format works on web browsers that support XUL. Its CSV export format is compatible with popular browsers and password managers like Mozilla Firefox, Google Chrome, Microsoft Edge, Opera, Brave, Vivaldi, KeePass, and KeePassXC. To import passwords from another browser's CSV password export use the [appropriate conversion tool](https://rjjiii.github.io/Password-Extractor/CSVtoXML.html).

## Formats

Password Extractor by default uses the same XML format as Password Backup Tool or Password Exporter. Those extensions both used a pseudo-CSV format with a header and hard-coded column. Password Extractor does not use the pseudo-CSV format. The CSV export-only option in Password Extractor should be compatible with Chrome, Firefox, Edge, Safari, and other common browsers (unlike the pseudo-CSV format). To import CSV files, you must first convert them to XML.

## Source Code and License

Password Extractor is a XUL-based extension to import or export passwords. It is a port of Password Backup Tool which is a Port of Password Exporter. The icon uses artwork from Lim Chee Aun's Phoenity Aura project under the LGPL. The rest of the extension is made available under the MPL 2.0.

To examine the source code simply extract the .xpi file with any archiver like 7-zip or Winzip. To recompile the extension, add the top-level directory to a .zip archive and replace the ".zip" extension with ".xpi" instead.
