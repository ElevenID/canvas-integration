// SPDX-License-Identifier: AGPL-3.0-only
// Internal strict JSON decoder shared by private service configuration readers.
export function parsePrivateJson(text) {
  const stack=[];
  for(let i=0;i<text.length;) {
    const char=text[i];
    if(char==='"') {
      const start=i++;
      while(i<text.length) {if(text[i]==='\\') i+=2;else if(text[i++]==='"') break;}
      const string=JSON.parse(text.slice(start,i));
      if(!string.isWellFormed()) throw new Error('invalid_private_configuration');
      const parent=stack.at(-1);
      if(parent?.object && parent.key) {
        if(parent.keys.has(string)) throw new Error('invalid_private_configuration');
        parent.keys.add(string);parent.key=false;
      }
      continue;
    }
    if(char==='{' || char==='[') {
      if(stack.length>=16) throw new Error('invalid_private_configuration');
      stack.push({object:char==='{',key:true,keys:new Set()});
    } else if(char==='}' || char===']') stack.pop();
    else if(char===',' && stack.at(-1)?.object) stack.at(-1).key=true;
    i++;
  }
  return JSON.parse(text);
}
