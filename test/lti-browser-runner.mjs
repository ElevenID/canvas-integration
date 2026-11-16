// SPDX-License-Identifier: AGPL-3.0-only
// Tooling is installed separately from the production connector package.
import { isAbsolute,dirname,join } from 'node:path';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { exerciseLtiBrowser } from './lti-browser-contract.mjs';

export async function runLtiBrowserContract(modulePath,info) {
  if(!isAbsolute(modulePath) || JSON.parse(await readFile(join(dirname(modulePath),'package.json'),'utf8')).version!=='1.59.1') {
    throw Error('pinned_browser_tooling_required');
  }
  const {chromium}=await import(pathToFileURL(modulePath).href);
  const browser=await chromium.launch({headless:true});
  try {
    const context=await browser.newContext({ignoreHTTPSErrors:true});
    try {
      const result=await exerciseLtiBrowser(await context.newPage(),info);
      if(result.passed!==9 || result.failed!==0) throw Error('incomplete_lti_browser_contract');
      console.log(JSON.stringify(result));return result;
    } finally {await context.close();}
  } finally {await browser.close();}
}
