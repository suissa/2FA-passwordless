export type Primitive=string|number|boolean;
export type Nominal<T extends Primitive,N extends string>=T&{readonly __semantic_atomic_behavior__:N};
export class SemanticAtomicBehavior<T extends Primitive,N extends string>{
  constructor(readonly name:N,readonly parse:(v:Primitive)=>T,readonly sanitize:(v:T)=>T,readonly normalize:(v:T)=>T,readonly logical:(v:T)=>boolean){}
  validate(input:unknown):Nominal<T,N>{
    let v=input;
    const seen=new Set<object>();
    while(v!==null&&typeof v==="object"&&"value" in v&&!seen.has(v as object)){seen.add(v as object);v=(v as any).value}
    if(typeof v!=="string"&&typeof v!=="number"&&typeof v!=="boolean")throw new Error(`[${this.name}] primitive required`);
    const parsed=this.parse(v);const sanitized=this.sanitize(parsed);const normalized=this.normalize(sanitized);
    if(!this.logical(normalized))throw new Error(`[${this.name}] logical validation failed`);
    return normalized as Nominal<T,N>
  }
}
export const WhatsAppNumber=new SemanticAtomicBehavior("WhatsAppNumber",String,v=>v.replace(/[\\s().-]/g,""),v=>v.startsWith("+")?v:`+${v}`,v=>/^\\+[1-9]\\d{10,14}$/.test(v));
export const ChatNumber=new SemanticAtomicBehavior("ChatNumber",String,v=>v.trim(),v=>v,v=>/^\\+[1-9]\\d{10,14}$/.test(v));
export const PasskeyCredential=new SemanticAtomicBehavior("PasskeyCredential",String,v=>v.trim(),v=>v,v=>v.length>=16);
export const SessionId=new SemanticAtomicBehavior("SessionId",String,v=>v.trim(),v=>v,v=>/^sess_[a-z0-9_-]+$/i.test(v));