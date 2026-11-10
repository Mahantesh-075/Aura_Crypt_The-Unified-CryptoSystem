const fs = require('fs');
const path = require('path');
const { getCSSLanguageService } = require('vscode-css-languageservice');
const { TextDocument } = require('vscode-languageserver-textdocument');

// 1. CSS Validation
console.log('====================================');
console.log('--- VALIDATING frontend/style.css ---');
console.log('====================================');
const cssService = getCSSLanguageService();
cssService.configure({
    validate: true,
    lint: {
        vendorPrefix: 'warning',
        emptyRules: 'warning',
        unknownProperties: 'warning',
        propertyIgnoredDueToDisplay: 'warning',
        compatibleVendorPrefixes: 'warning'
    }
});

const cssPath = path.resolve(__dirname, '../frontend/style.css');
const cssContent = fs.readFileSync(cssPath, 'utf-8');
const cssDoc = TextDocument.create('file:///frontend/style.css', 'css', 1, cssContent);
const stylesheet = cssService.parseStylesheet(cssDoc);

const cssDiagnostics = cssService.doValidation(cssDoc, stylesheet);

console.log(`Found ${cssDiagnostics.length} CSS diagnostic(s):`);
cssDiagnostics.forEach(d => {
    const sev = d.severity === 1 ? 'ERROR' : d.severity === 2 ? 'WARNING' : 'INFO';
    console.log(`[${sev}] Line ${d.range.start.line + 1}:${d.range.start.character + 1} - ${d.message} (code: ${d.code})`);
});

// 2. HTML Validation
console.log('\n====================================');
console.log('--- VALIDATING frontend/index.html ---');
console.log('====================================');
const htmlPath = path.resolve(__dirname, '../frontend/index.html');
const htmlContent = fs.readFileSync(htmlPath, 'utf-8');

// HTML tag structure validation
const voidTags = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr']);
const tagRegex = /<\/?([a-zA-Z0-9\-]+)([^>]*)>/g;
const stack = [];
const htmlErrors = [];

let match;
while ((match = tagRegex.exec(htmlContent)) !== null) {
    const fullTag = match[0];
    const tagName = match[1].toLowerCase();
    const isClosing = fullTag.startsWith('</');
    const isSelfClosing = fullTag.endsWith('/>') || voidTags.has(tagName);
    
    // Find line number
    const line = htmlContent.substring(0, match.index).split('\n').length;

    if (isClosing) {
        if (voidTags.has(tagName)) continue;
        if (stack.length === 0) {
            htmlErrors.push({ line, msg: `Unexpected closing tag </${tagName}> without matching open tag` });
        } else {
            const top = stack.pop();
            if (top.name !== tagName) {
                htmlErrors.push({ line, msg: `Mismatched tag: expected </${top.name}> (opened line ${top.line}), but found </${tagName}>` });
            }
        }
    } else if (!isSelfClosing) {
        stack.push({ name: tagName, line });
    }
}

while (stack.length > 0) {
    const top = stack.pop();
    htmlErrors.push({ line: top.line, msg: `Unclosed tag <${top.name}> opened at line ${top.line}` });
}

console.log(`Found ${htmlErrors.length} HTML error(s):`);
htmlErrors.forEach(e => {
    console.log(`[ERROR] Line ${e.line}: ${e.msg}`);
});
