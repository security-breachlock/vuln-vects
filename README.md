# Vuln/Vects
A powerful, flexible CVSS parser, calculator and validator written for JavaScript/TypeScript.

![Logo](logo-readme.svg)

## Overview
Vuln/Vects is a library written in TypeScript, targeting JavaScript (server-side [Node.js](https://nodejs.org/en/) or
browser) that aims to provide all the generation, validation, scoring and manipulation functionality you could ever need
when working with CVSS (common vulnerability scoring system) vectors of any version. CVSS v2, v3.0 and v3.1 are
currently supported.

## Installing
Installing the project is very straightforward via [npm](https://www.npmjs.com/):

```bash
npm install --save vuln-vects
```

If you're working in TypeScript and need type annotations etc. you might also want to run:

```bash
npm install --save @types/vuln-vects
```

## Building
It's only necessary to build the project if you're doing development work on it. There's no need to do so if you're just installing it to use as a library. Ensure that [Node.js v14.x](https://nodejs.org/en/) and npm is installed and run:

```bash
npm run build
```

Build output is to `/dist`. To build accompanying documentation, you need the following command:

```bash
npm run docs
```

Documentation is generated using [TypeDoc](https://typedoc.org/) and rendered as HTML to `/docs`.

## Bundling
You'll need to bundle the library if you want to use it in-browser (remember to build it first):

```bash
npm run build && npm run bundle
```

This will give you a single file in `/bundle` that you can import into your webpages (see [Usage](#usage) section).

## Running tests
Tests are on [Mocha](https://mochajs.org/) and [Chai](https://www.chaijs.com/). You can run them like so:

```bash
npm run test
```

## Usage
Usage of the library will vary, depending on whether you want to run in-browser or as part of a server-side Node.js project. In any case, you'll need to begin by installing the library:

```bash
npm install --save vuln-vects
```

### In the browser
Usage in the browser is super straightforward. After installation, simply import the bundled library into your webpage like so:

```html
<script src="node_modules/vuln-vects/bundle/vuln-vects.js"></script>
```

You'll then get a `VulnVects` object in the global namespace through which you can use the library:

```js
<script>
    alert(VulnVects.parseCvss2Vector('CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N').baseScore); // Shows '5.0'.
</script>
```

### On the server
Importing and invoking the library is slightly different on the server side.

```js
import { parseCvss2Vector } from 'vuln-vects';

console.log(parseCvss2Vector('CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N').baseScore); // Prints '5.0'.
```

Aside from this, the API is identical. There is a lot more you can do with the library aside from just the above. See [Features](#features) for more details.

## Features

### Validating

### Scoring

### Rendering

### Mocking

