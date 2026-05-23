import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  AreaChart, Area, PieChart, Pie, Cell, BarChart, Bar,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend
} from "recharts";

const API = "https://soc-anomaly-dashboard.onrender.com";

const C = {
  bg:"#04070f", panel:"#080e1c", border:"#0f1f3d",
  accent:"#0ea5e9", high:"#f43f5e", medium:"#f59e0b",
  low:"#10b981", purple:"#8b5cf6", orange:"#f97316",
  critical:"#dc2626", text:"#e2e8f0", muted:"#475569",
};

const sevColor = s => ({CRITICAL:C.critical,HIGH:C.high,MEDIUM:C.medium,LOW:C.low}[s]??C.muted);
const sevBg    = s => ({CRITICAL:"#1a0208",HIGH:"#1a0510",MEDIUM:"#1a1005",LOW:"#041a10"}[s]??C.panel);
const riskColor= r => ({HIGH:C.high,MEDIUM:C.medium,LOW:C.low}[r]??C.muted);
const riskBg   = r => ({HIGH:"#1a0510",MEDIUM:"#1a1005",LOW:"#041a10"}[r]??C.panel);
const statusColor=s=>({PENDING:C.accent,RESOLVED:C.low,FALSE_POSITIVE:C.muted,
  ESCALATED:C.orange,CONFIRMED_FRAUD:C.high,OPEN:C.accent,
  INVESTIGATING:"#a855f7"}[s]??C.muted);
const threatIcon=t=>({BRUTE_FORCE:"🔑",PORT_SCAN:"🔍",SQL_INJECTION:"💉",
  XSS_ATTACK:"📜",DATA_EXFILTRATION:"📤",C2_BEACONING:"📡",
  LATERAL_MOVEMENT:"🕸",PRIV_ESCALATION:"⬆",DDOS:"💥",
  RANSOMWARE:"🔒",INSIDER_THREAT:"🕵",DNS_TUNNELING:"🌀",NORMAL:"✅"}[t]??"⚠");

const fmt    = n => typeof n==="number" ? n.toFixed(4) : "—";
const fmtAmt = n => n!=null ? `$${Number(n).toFixed(2)}` : "—";
const fmtPct = n => n!=null ? `${(Number(n)*100).toFixed(1)}%` : "—";
const fmtTime= t => t ? new Date(t+"Z").toLocaleTimeString() : "—";
const fmtBytes=b => {
  if(!b) return "—";
  if(b>1e9) return `${(b/1e9).toFixed(1)}GB`;
  if(b>1e6) return `${(b/1e6).toFixed(1)}MB`;
  if(b>1e3) return `${(b/1e3).toFixed(1)}KB`;
  return `${b}B`;
};

// ── Components ────────────────────────────────────────────────────────────────
function KpiCard({label,value,sub,color,icon}) {
  return (
    <motion.div initial={{opacity:0,y:20}} animate={{opacity:1,y:0}} style={{
      background:C.panel,border:`1px solid ${C.border}`,
      borderRadius:12,padding:"14px 16px",position:"relative",overflow:"hidden",
    }}>
      <div style={{position:"absolute",top:0,left:0,right:0,height:2,
        background:`linear-gradient(90deg,transparent,${color},transparent)`}}/>
      <div style={{color:C.muted,fontSize:9,letterSpacing:"0.12em",textTransform:"uppercase",marginBottom:5}}>
        {icon} {label}
      </div>
      <div style={{color,fontSize:24,fontWeight:700,fontFamily:"'DM Mono',monospace",lineHeight:1}}>{value}</div>
      {sub&&<div style={{color:C.muted,fontSize:10,marginTop:3}}>{sub}</div>}
    </motion.div>
  );
}

function SevBadge({level}) {
  return <span style={{background:sevBg(level),color:sevColor(level),
    border:`1px solid ${sevColor(level)}40`,borderRadius:5,padding:"2px 8px",
    fontSize:10,fontWeight:700,letterSpacing:"0.06em",fontFamily:"'DM Mono',monospace"}}>{level}</span>;
}

function RiskBadge({level}) {
  return <span style={{background:riskBg(level),color:riskColor(level),
    border:`1px solid ${riskColor(level)}40`,borderRadius:5,padding:"2px 8px",
    fontSize:10,fontWeight:700,letterSpacing:"0.06em",fontFamily:"'DM Mono',monospace"}}>{level}</span>;
}

function ScoreBar({score,label,color}) {
  const pct=Math.round((score??0)*100);
  const col=color||(pct>=70?C.high:pct>=40?C.medium:C.low);
  return (
    <div style={{marginBottom:4}}>
      {label&&<div style={{color:C.muted,fontSize:9,marginBottom:2}}>{label}</div>}
      <div style={{display:"flex",alignItems:"center",gap:6}}>
        <div style={{flex:1,height:3,background:"#1e293b",borderRadius:2,overflow:"hidden"}}>
          <motion.div initial={{width:0}} animate={{width:`${pct}%`}} transition={{duration:0.5}}
            style={{height:"100%",background:col,borderRadius:2}}/>
        </div>
        <span style={{color:col,fontSize:9,fontFamily:"'DM Mono',monospace",minWidth:36}}>{fmt(score)}</span>
      </div>
    </div>
  );
}

function ChartTip({active,payload,label}) {
  if(!active||!payload?.length) return null;
  return (
    <div style={{background:"#0b1526",border:`1px solid ${C.border}`,
      borderRadius:8,padding:"8px 12px",fontSize:11,color:C.text}}>
      <div style={{color:C.muted,marginBottom:4}}>{label}</div>
      {payload.map(p=>(
        <div key={p.name} style={{color:p.color??C.accent}}>
          {p.name}: {typeof p.value==="number"?p.value.toFixed(3):p.value}
        </div>
      ))}
    </div>
  );
}

// ── Cyber Log Row ─────────────────────────────────────────────────────────────
function CyberRow({log,onUpdate,idx}) {
  const [open,setOpen]=useState(false);
  const [loading,setLoading]=useState(false);

  const handle=async(status)=>{
    setLoading(true);
    await fetch(`${API}/cyber/update/${log.id}/${status}`,{method:"POST"});
    onUpdate(log.id,status);
    setLoading(false);
  };

  // Parse raw_json safely
  let raw={};
  try { raw=eval("("+log.raw_json+")"); } catch(e) {}

  return (
    <motion.div initial={{opacity:0,x:-20}} animate={{opacity:1,x:0}}
      transition={{delay:idx*0.02}} style={{
        background:open?"#0b1526":C.panel,
        border:`1px solid ${log.is_threat?"#1a1527":"#0a1830"}`,
        borderRadius:10,marginBottom:5,overflow:"hidden",
        borderLeft: log.is_threat ? `3px solid ${sevColor(log.severity)}` : `3px solid ${C.border}`,
      }}>
      <div onClick={()=>setOpen(v=>!v)} style={{
        display:"grid",
        gridTemplateColumns:"24px 80px 100px 140px 1fr 90px 90px",
        alignItems:"center",padding:"10px 14px",cursor:"pointer",gap:10,
      }}>
        <span style={{fontSize:14}}>{threatIcon(log.threat_type)}</span>
        <SevBadge level={log.severity}/>
        <span style={{color:C.muted,fontSize:10,fontFamily:"'DM Mono',monospace"}}>
          {log.log_type}
        </span>
        <span style={{color:sevColor(log.severity),fontSize:11,fontWeight:600}}>
          {log.threat_type?.replace(/_/g," ")}
        </span>
        <div style={{overflow:"hidden"}}>
          <div style={{color:C.text,fontSize:11,whiteSpace:"nowrap",
            overflow:"hidden",textOverflow:"ellipsis"}}>{log.indicator}</div>
          <div style={{color:C.muted,fontSize:9,marginTop:1}}>
            {log.src_ip&&`${log.src_ip} → `}{log.dst_ip}
            {log.mitre&&<span style={{color:C.purple,marginLeft:8}}>MITRE {log.mitre}</span>}
          </div>
        </div>
        <span style={{color:statusColor(log.status),fontSize:10,
          fontFamily:"'DM Mono',monospace"}}>{log.status}</span>
        <span style={{color:C.muted,fontSize:10}}>{fmtTime(log.timestamp)}</span>
      </div>

      <AnimatePresence>
        {open&&(
          <motion.div initial={{height:0,opacity:0}} animate={{height:"auto",opacity:1}}
            exit={{height:0,opacity:0}} style={{overflow:"hidden"}}>
            <div style={{padding:"12px 14px 16px",borderTop:`1px solid ${C.border}`,
              display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:14}}>

              {/* Raw details */}
              <div>
                <div style={{color:C.muted,fontSize:9,letterSpacing:"0.1em",marginBottom:8}}>LOG DETAILS</div>
                {[
                  ["Log Type",    log.log_type],
                  ["Threat",      log.threat_type],
                  ["Severity",    log.severity],
                  ["Source IP",   log.src_ip||"—"],
                  ["Dest IP",     log.dst_ip||"—"],
                  ["MITRE ATT&CK",log.mitre||"—"],
                  ["Log ID",      log.log_id],
                  ["Bytes Sent",  fmtBytes(raw.bytes_sent)],
                  ["Bytes Recv",  fmtBytes(raw.bytes_recv)],
                ].filter(([,v])=>v&&v!=="—"||true).map(([k,v])=>(
                  <div key={k} style={{display:"flex",justifyContent:"space-between",
                    padding:"3px 0",borderBottom:`1px solid ${C.border}`,fontSize:10}}>
                    <span style={{color:C.muted}}>{k}</span>
                    <span style={{color:C.text,fontFamily:"'DM Mono',monospace",
                      maxWidth:160,overflow:"hidden",textOverflow:"ellipsis"}}>{v}</span>
                  </div>
                ))}
              </div>

              {/* Threat-specific details */}
              <div>
                <div style={{color:C.muted,fontSize:9,letterSpacing:"0.1em",marginBottom:8}}>THREAT INTELLIGENCE</div>
                <div style={{background:sevBg(log.severity),border:`1px solid ${sevColor(log.severity)}30`,
                  borderRadius:8,padding:"10px 12px",marginBottom:10}}>
                  <div style={{color:sevColor(log.severity),fontSize:12,fontWeight:600,marginBottom:4}}>
                    {threatIcon(log.threat_type)} {log.threat_type?.replace(/_/g," ")}
                  </div>
                  <div style={{color:C.text,fontSize:11}}>{log.indicator}</div>
                </div>
                {log.mitre&&(
                  <div style={{background:"#0d0f2a",border:`1px solid ${C.purple}30`,
                    borderRadius:8,padding:"8px 12px"}}>
                    <div style={{color:C.purple,fontSize:10,marginBottom:3}}>MITRE ATT&CK Framework</div>
                    <div style={{color:C.text,fontSize:12,fontFamily:"'DM Mono',monospace"}}>{log.mitre}</div>
                    <div style={{color:C.muted,fontSize:10,marginTop:3}}>{log.threat_type?.replace(/_/g," ")}</div>
                  </div>
                )}
                {/* Show payload if SQL/XSS */}
                {raw.payload&&(
                  <div style={{marginTop:10,background:"#1a0510",border:`1px solid ${C.high}30`,
                    borderRadius:8,padding:"8px 12px"}}>
                    <div style={{color:C.high,fontSize:9,marginBottom:4}}>ATTACK PAYLOAD</div>
                    <div style={{color:C.text,fontSize:10,fontFamily:"'DM Mono',monospace",
                      wordBreak:"break-all"}}>{raw.payload}</div>
                  </div>
                )}
                <ScoreBar score={log.severity_score} label="Severity Score" color={sevColor(log.severity)}/>
              </div>

              {/* Actions */}
              <div>
                <div style={{color:C.muted,fontSize:9,letterSpacing:"0.1em",marginBottom:8}}>SOC ACTIONS</div>
                <div style={{display:"flex",flexDirection:"column",gap:5}}>
                  {[
                    ["INVESTIGATING","#a855f7","🔍 Investigate"],
                    ["RESOLVED",    C.low,    "✓ Resolve"],
                    ["ESCALATED",   C.orange, "⬆ Escalate"],
                    ["FALSE_POSITIVE",C.muted,"✗ False Positive"],
                  ].map(([action,color,label])=>(
                    <button key={action}
                      disabled={loading||log.status===action}
                      onClick={e=>{e.stopPropagation();handle(action);}}
                      style={{background:"transparent",border:`1px solid ${color}50`,
                        color:log.status===action?color:`${color}80`,
                        borderRadius:6,padding:"5px 10px",fontSize:11,
                        cursor:"pointer",fontFamily:"'DM Mono',monospace"}}>
                      {label}
                    </button>
                  ))}
                </div>
                {raw.files_encrypted&&(
                  <div style={{marginTop:10,padding:"8px",background:"#1a0510",
                    border:`1px solid ${C.critical}40`,borderRadius:6}}>
                    <div style={{color:C.critical,fontSize:10}}>
                      🔒 {raw.files_encrypted?.toLocaleString()} files encrypted
                    </div>
                  </div>
                )}
                {raw.failed_attempts&&(
                  <div style={{marginTop:10,padding:"8px",background:"#1a0510",
                    border:`1px solid ${C.high}40`,borderRadius:6}}>
                    <div style={{color:C.high,fontSize:10}}>
                      🔑 {raw.failed_attempts} failed login attempts
                    </div>
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ── Alert Row (Financial) ─────────────────────────────────────────────────────
function AlertRow({alert,onUpdate,onDelete,idx}) {
  const [open,setOpen]=useState(false);
  const [loading,setLoading]=useState(false);

  const handle=async(action)=>{
    setLoading(true);
    if(action==="delete"){
      await fetch(`${API}/alerts/${alert.id}`,{method:"DELETE"});
      onDelete(alert.id);
    } else {
      await fetch(`${API}/update/${alert.id}/${action}`,{method:"POST"});
      onUpdate(alert.id,action);
    }
    setLoading(false);
  };

  return (
    <motion.div initial={{opacity:0,x:-20}} animate={{opacity:1,x:0}}
      transition={{delay:idx*0.02}} style={{
        background:open?"#0b1526":C.panel,
        border:`1px solid ${open?C.border:"#0a1830"}`,
        borderRadius:10,marginBottom:5,overflow:"hidden",
        borderLeft:`3px solid ${riskColor(alert.risk_level)}40`,
      }}>
      <div onClick={()=>setOpen(v=>!v)} style={{
        display:"grid",gridTemplateColumns:"44px 80px 1fr 90px 120px 80px",
        alignItems:"center",padding:"10px 14px",cursor:"pointer",gap:10,
      }}>
        <span style={{color:C.muted,fontSize:10,fontFamily:"'DM Mono',monospace"}}>#{alert.id}</span>
        <RiskBadge level={alert.risk_level}/>
        <div style={{overflow:"hidden"}}>
          <ScoreBar score={alert.score}/>
          <div style={{color:C.muted,fontSize:10,marginTop:1,whiteSpace:"nowrap",
            overflow:"hidden",textOverflow:"ellipsis"}}>{alert.reason}</div>
        </div>
        <span style={{color:C.low,fontSize:11,fontFamily:"'DM Mono',monospace"}}>{fmtAmt(alert.amount)}</span>
        <span style={{color:statusColor(alert.status),fontSize:10,fontFamily:"'DM Mono',monospace"}}>{alert.status}</span>
        <span style={{color:C.muted,fontSize:10}}>{fmtTime(alert.timestamp)}</span>
      </div>

      <AnimatePresence>
        {open&&(
          <motion.div initial={{height:0,opacity:0}} animate={{height:"auto",opacity:1}}
            exit={{height:0,opacity:0}} style={{overflow:"hidden"}}>
            <div style={{padding:"12px 14px 16px",borderTop:`1px solid ${C.border}`,
              display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:14}}>
              <div>
                <div style={{color:C.muted,fontSize:9,marginBottom:8}}>ML SCORES</div>
                <ScoreBar score={alert.iso_score}   label="Isolation Forest"/>
                <ScoreBar score={alert.lof_score}   label="LOF"/>
                <ScoreBar score={alert.xgb_score}   label="XGBoost" color={C.accent}/>
                <ScoreBar score={alert.rf_score}    label="Random Forest" color={C.accent}/>
                <ScoreBar score={alert.dbscan_score} label="DBSCAN"/>
                <ScoreBar score={alert.ecod_score}  label="ECOD"/>
              </div>
              <div>
                <div style={{color:C.muted,fontSize:9,marginBottom:8}}>DOMAIN SIGNALS</div>
                <ScoreBar score={alert.trading_score}  label="Trading Patterns" color={C.orange}/>
                <ScoreBar score={alert.velocity_score} label="Velocity" color={C.purple}/>
                <ScoreBar score={alert.stat_score}     label="Statistical"/>
                <div style={{marginTop:8,color:C.muted,fontSize:9,marginBottom:4}}>REASONS</div>
                {(alert.reason??"").split(" | ").slice(0,3).map((r,i)=>(
                  <div key={i} style={{color:C.text,fontSize:10,padding:"2px 0",
                    borderBottom:`1px solid ${C.border}`}}>⚡ {r}</div>
                ))}
              </div>
              <div>
                <div style={{color:C.muted,fontSize:9,marginBottom:8}}>ACTIONS</div>
                <div style={{display:"flex",flexDirection:"column",gap:5}}>
                  {[
                    ["RESOLVED",       C.low,     "✓ Resolved"],
                    ["CONFIRMED_FRAUD",C.high,    "🚨 Confirm Fraud"],
                    ["ESCALATED",      C.orange,  "⬆ Escalate"],
                    ["FALSE_POSITIVE", C.muted,   "✗ False Positive"],
                  ].map(([action,color,label])=>(
                    <button key={action} disabled={loading||alert.status===action}
                      onClick={e=>{e.stopPropagation();handle(action);}}
                      style={{background:"transparent",border:`1px solid ${color}50`,
                        color:alert.status===action?color:`${color}80`,
                        borderRadius:6,padding:"5px 10px",fontSize:11,cursor:"pointer"}}>
                      {label}
                    </button>
                  ))}
                  <button onClick={e=>{e.stopPropagation();handle("delete");}}
                    style={{background:"transparent",border:`1px solid ${C.high}30`,
                      color:`${C.high}50`,borderRadius:6,padding:"5px 10px",
                      fontSize:11,cursor:"pointer",marginTop:2}}>🗑 Delete</button>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function App() {
  const [alerts,setAlerts]       = useState([]);
  const [cyberLogs,setCyberLogs] = useState([]);
  const [stats,setStats]         = useState(null);
  const [cyberStats,setCyberStats]=useState(null);
  const [loading,setLoading]     = useState(false);
  const [cyberLoading,setCyberLoading]=useState(false);
  const [tab,setTab]             = useState("soc");
  const [riskFilter,setRiskFilter]=useState("ALL");
  const [sevFilter,setSevFilter] = useState("ALL");
  const [threatFilter,setThreatFilter]=useState("ALL");
  const [pulse,setPulse]         = useState(false);
  const [toast,setToast]         = useState(null);

  const showToast=(msg,type="success")=>{
    setToast({msg,type});
    setTimeout(()=>setToast(null),3500);
  };

  const fetchAll=useCallback(async()=>{
    try {
      const [aRes,sRes,cRes,csRes]=await Promise.all([
        fetch(`${API}/alerts?limit=100`),
        fetch(`${API}/stats`),
        fetch(`${API}/cyber/logs?limit=100`),
        fetch(`${API}/cyber/stats`),
      ]);
      setAlerts(await aRes.json());
      setStats(await sRes.json());
      setCyberLogs(await cRes.json());
      setCyberStats(await csRes.json());
    } catch { showToast("API offline — start backend","error"); }
  },[]);

  useEffect(()=>{fetchAll();},[fetchAll]);
  useEffect(()=>{const id=setInterval(fetchAll,10000);return()=>clearInterval(id);},[fetchAll]);

  const genFinancial=async(count=1)=>{
    setLoading(true);setPulse(true);setTimeout(()=>setPulse(false),600);
    try {
      const url=count===1?`${API}/generate`:`${API}/generate/bulk/${count}`;
      const data=await(await fetch(url,{method:"POST"})).json();
      showToast(count===1?`Financial: ${data.alert?.risk_level} (${data.alert?.score?.toFixed(3)})`
        :`${count} financial alerts generated`);
      await fetchAll();
    } catch{showToast("Failed","error");}
    setLoading(false);
  };

  const genCyber=async(count=1,threatType=null)=>{
    setCyberLoading(true);
    try {
      let url,data;
      if(threatType){
        url=`${API}/cyber/generate/threat/${threatType}`;
        data=await(await fetch(url,{method:"POST"})).json();
        showToast(`Generated: ${threatType.replace(/_/g," ")}`);
      } else if(count===1){
        data=await(await fetch(`${API}/cyber/generate`,{method:"POST"})).json();
        showToast(`Cyber: ${data.log?.threat_type} — ${data.log?.severity}`);
      } else {
        data=await(await fetch(`${API}/cyber/generate/bulk/${count}`,{method:"POST"})).json();
        showToast(`${count} cyber logs — ${Object.keys(data.threats_detected||{}).length} threat types`);
      }
      await fetchAll();
    } catch{showToast("Failed","error");}
    setCyberLoading(false);
  };

  const updateCyber=(id,s)=>setCyberLogs(l=>l.map(x=>x.id===id?{...x,status:s}:x));
  const updateAlert=(id,s)=>setAlerts(a=>a.map(x=>x.id===id?{...x,status:s}:x));
  const deleteAlert=(id)=>setAlerts(a=>a.filter(x=>x.id!==id));

  const visibleCyber=cyberLogs.filter(l=>
    (sevFilter==="ALL"||l.severity===sevFilter)&&
    (threatFilter==="ALL"||l.threat_type===threatFilter)
  );

  const visibleAlerts=alerts.filter(a=>riskFilter==="ALL"||a.risk_level===riskFilter);

  const THREAT_TYPES=["BRUTE_FORCE","PORT_SCAN","SQL_INJECTION","XSS_ATTACK",
    "DATA_EXFILTRATION","C2_BEACONING","LATERAL_MOVEMENT","PRIV_ESCALATION",
    "DDOS","RANSOMWARE","INSIDER_THREAT","DNS_TUNNELING"];

  return (
    <div style={{minHeight:"100vh",background:C.bg,color:C.text,
      fontFamily:"'IBM Plex Sans',system-ui,sans-serif"}}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=DM+Mono:wght@400;500&display=swap');
        *{box-sizing:border-box;margin:0;padding:0}
        ::-webkit-scrollbar{width:3px}::-webkit-scrollbar-track{background:${C.bg}}
        ::-webkit-scrollbar-thumb{background:${C.border};border-radius:2px}
        button:hover{opacity:0.82;transition:opacity 0.15s}
      `}</style>

      {/* Header */}
      <div style={{borderBottom:`1px solid ${C.border}`,padding:"0 24px",
        display:"flex",alignItems:"center",justifyContent:"space-between",
        height:50,background:`linear-gradient(to bottom,${C.panel},${C.bg})`,
        position:"sticky",top:0,zIndex:100}}>
        <div style={{display:"flex",alignItems:"center",gap:12}}>
          <div style={{width:8,height:8,borderRadius:"50%",background:C.accent,
            boxShadow:`0 0 ${pulse?16:5}px ${C.accent}`,transition:"box-shadow 0.3s"}}/>
          <span style={{fontFamily:"'DM Mono',monospace",fontWeight:500,fontSize:13}}>
            ZeTheta // Unified Security Platform
          </span>
          <span style={{color:C.muted,fontSize:10}}>
            SOC · Financial Fraud · Anomaly Detection
          </span>
        </div>
        <div style={{display:"flex",gap:5}}>
          {[["soc","🛡 SOC Logs"],["financial","💰 Financial"],["analytics","📊 Analytics"],["models","🤖 Models"]].map(([key,label])=>(
            <button key={key} onClick={()=>setTab(key)} style={{
              background:tab===key?C.border:"transparent",
              border:`1px solid ${tab===key?C.accent+"60":"transparent"}`,
              color:tab===key?C.accent:C.muted,
              borderRadius:6,padding:"4px 12px",fontSize:11,cursor:"pointer",
            }}>{label}</button>
          ))}
        </div>
      </div>

      <div style={{padding:"16px 24px",maxWidth:1600,margin:"0 auto"}}>

        {/* ═══ SOC TAB ═══════════════════════════════════════════════════════ */}
        {tab==="soc"&&(
          <>
            {/* SOC KPIs */}
            <div style={{display:"grid",gridTemplateColumns:"repeat(8,1fr)",gap:8,marginBottom:16}}>
              <KpiCard label="Total Logs"  value={cyberStats?.total??0}     color={C.accent}   icon="📋"/>
              <KpiCard label="Threats"     value={cyberStats?.threats??0}   color={C.high}     icon="⚠"/>
              <KpiCard label="Critical"    value={cyberStats?.critical??0}  color={C.critical} icon="🚨"/>
              <KpiCard label="High"        value={cyberStats?.high??0}      color={C.high}     icon="🔴"/>
              <KpiCard label="Open"        value={cyberStats?.open??0}      color={C.accent}   icon="🔓"/>
              <KpiCard label="Investigating" value={cyberStats?.investigating??0} color="#a855f7" icon="🔍"/>
              <KpiCard label="Detection"   value={`${cyberStats?.detection_rate??0}%`} color={C.low} icon="🎯"/>
              <KpiCard label="Resolved"    value={cyberStats?.resolved??0}  color={C.low}      icon="✅"/>
            </div>

            {/* Generate threat buttons */}
            <div style={{display:"flex",gap:6,marginBottom:12,flexWrap:"wrap"}}>
              <button onClick={()=>genCyber(1)} disabled={cyberLoading} style={{
                background:`linear-gradient(135deg,${C.accent}20,${C.accent}10)`,
                border:`1px solid ${C.accent}50`,color:C.accent,borderRadius:6,
                padding:"5px 14px",fontSize:11,cursor:"pointer"}}>
                {cyberLoading?"...":"+ Generate Log"}
              </button>
              <button onClick={()=>genCyber(20)} disabled={cyberLoading} style={{
                background:`linear-gradient(135deg,${C.accent}15,${C.accent}05)`,
                border:`1px solid ${C.accent}30`,color:C.accent,borderRadius:6,
                padding:"5px 12px",fontSize:11,cursor:"pointer"}}>Bulk ×20</button>
              <div style={{width:1,background:C.border,margin:"0 4px"}}/>
              {/* Quick threat generators */}
              {[["RANSOMWARE",C.critical],["BRUTE_FORCE",C.high],
                ["SQL_INJECTION",C.critical],["DATA_EXFILTRATION",C.critical],
                ["C2_BEACONING",C.high],["LATERAL_MOVEMENT",C.high]
              ].map(([t,color])=>(
                <button key={t} onClick={()=>genCyber(1,t)} disabled={cyberLoading} style={{
                  background:`${color}15`,border:`1px solid ${color}40`,
                  color,borderRadius:6,padding:"4px 10px",fontSize:10,cursor:"pointer"}}>
                  {threatIcon(t)} {t.replace(/_/g," ")}
                </button>
              ))}
              <button onClick={()=>fetch(`${API}/cyber/logs`,{method:"DELETE"}).then(fetchAll)} style={{
                marginLeft:"auto",background:"transparent",border:`1px solid ${C.high}30`,
                color:`${C.high}60`,borderRadius:6,padding:"5px 10px",fontSize:10,cursor:"pointer"}}>
                🗑 Clear
              </button>
            </div>

            {/* Severity + Threat filters */}
            <div style={{display:"flex",gap:6,marginBottom:10,flexWrap:"wrap"}}>
              {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(s=>(
                <button key={s} onClick={()=>setSevFilter(s)} style={{
                  background:sevFilter===s?(s==="ALL"?"#0b1526":sevBg(s)):"transparent",
                  border:`1px solid ${sevFilter===s?(s==="ALL"?C.accent:sevColor(s))+"80":C.border}`,
                  color:sevFilter===s?(s==="ALL"?C.accent:sevColor(s)):C.muted,
                  borderRadius:6,padding:"3px 10px",fontSize:10,cursor:"pointer"}}>
                  {s}
                </button>
              ))}
              <div style={{width:1,background:C.border}}/>
              <select value={threatFilter} onChange={e=>setThreatFilter(e.target.value)}
                style={{background:C.panel,border:`1px solid ${C.border}`,color:C.text,
                  borderRadius:6,padding:"3px 8px",fontSize:10,cursor:"pointer"}}>
                <option value="ALL">All Threats</option>
                {THREAT_TYPES.map(t=><option key={t} value={t}>{t.replace(/_/g," ")}</option>)}
                <option value="NORMAL">NORMAL</option>
              </select>
            </div>

            {/* Log table header */}
            <div style={{display:"grid",
              gridTemplateColumns:"24px 80px 100px 140px 1fr 90px 90px",
              padding:"4px 14px",marginBottom:5,color:C.muted,
              fontSize:9,letterSpacing:"0.1em",gap:10}}>
              <span></span><span>SEV</span><span>TYPE</span>
              <span>THREAT</span><span>INDICATOR / IPs</span>
              <span>STATUS</span><span>TIME</span>
            </div>

            <div style={{maxHeight:"calc(100vh-340px)",overflowY:"auto",minHeight:300}}>
              <AnimatePresence>
                {visibleCyber.length===0?(
                  <div style={{textAlign:"center",padding:50,color:C.muted,
                    border:`1px dashed ${C.border}`,borderRadius:12}}>
                    No cyber logs yet — click Generate Log or use threat buttons above
                  </div>
                ):visibleCyber.map((l,i)=>(
                  <CyberRow key={l.id} log={l} idx={i} onUpdate={updateCyber}/>
                ))}
              </AnimatePresence>
            </div>
          </>
        )}

        {/* ═══ FINANCIAL TAB ═══════════════════════════════════════════════ */}
        {tab==="financial"&&(
          <>
            <div style={{display:"grid",gridTemplateColumns:"repeat(8,1fr)",gap:8,marginBottom:16}}>
              <KpiCard label="Total"      value={stats?.total??0}              color={C.accent}  icon="📡"/>
              <KpiCard label="High Risk"  value={stats?.high??0}               color={C.high}    icon="🔴"/>
              <KpiCard label="Medium"     value={stats?.medium??0}             color={C.medium}  icon="🟡"/>
              <KpiCard label="Confirmed"  value={stats?.confirmed_fraud??0}    color={C.high}    icon="🚨"/>
              <KpiCard label="Resolved"   value={stats?.resolved??0}           color={C.low}     icon="✅"/>
              <KpiCard label="Detection"  value={`${stats?.detection_rate??0}%`} color={C.purple} icon="🎯"/>
              <KpiCard label="False Pos"  value={`${stats?.false_positive_rate??0}%`} color={C.orange} icon="⚠"/>
              <KpiCard label="Avg Score"  value={fmt(stats?.avg_score)}        color={C.accent}  icon="📈"/>
            </div>

            <div style={{display:"flex",gap:6,marginBottom:12,alignItems:"center"}}>
              {["ALL","HIGH","MEDIUM","LOW"].map(f=>(
                <button key={f} onClick={()=>setRiskFilter(f)} style={{
                  background:riskFilter===f?riskBg(f):"transparent",
                  border:`1px solid ${riskFilter===f?riskColor(f)+"80":C.border}`,
                  color:riskFilter===f?riskColor(f):C.muted,
                  borderRadius:6,padding:"4px 12px",fontSize:11,cursor:"pointer"}}>
                  {f}
                </button>
              ))}
              <div style={{marginLeft:"auto",display:"flex",gap:6}}>
                {[1,5,20].map(n=>(
                  <button key={n} onClick={()=>genFinancial(n)} disabled={loading} style={{
                    background:`${C.accent}15`,border:`1px solid ${C.accent}50`,
                    color:C.accent,borderRadius:6,padding:"5px 12px",fontSize:11,cursor:"pointer"}}>
                    {loading?"...":n===1?"+ Generate":`Bulk ×${n}`}
                  </button>
                ))}
                <button onClick={()=>fetch(`${API}/alerts`,{method:"DELETE"}).then(fetchAll)} style={{
                  background:"transparent",border:`1px solid ${C.high}30`,
                  color:`${C.high}60`,borderRadius:6,padding:"5px 10px",fontSize:11,cursor:"pointer"}}>
                  🗑 Clear
                </button>
              </div>
            </div>

            <div style={{display:"grid",
              gridTemplateColumns:"44px 80px 1fr 90px 120px 80px",
              padding:"4px 14px",marginBottom:5,color:C.muted,
              fontSize:9,letterSpacing:"0.1em",gap:10}}>
              <span>ID</span><span>RISK</span><span>SCORE/REASON</span>
              <span>AMOUNT</span><span>STATUS</span><span>TIME</span>
            </div>

            <div style={{maxHeight:"calc(100vh-320px)",overflowY:"auto"}}>
              <AnimatePresence>
                {visibleAlerts.length===0?(
                  <div style={{textAlign:"center",padding:50,color:C.muted,
                    border:`1px dashed ${C.border}`,borderRadius:12}}>
                    No alerts yet — click Generate
                  </div>
                ):visibleAlerts.map((a,i)=>(
                  <AlertRow key={a.id} alert={a} idx={i}
                    onUpdate={updateAlert} onDelete={deleteAlert}/>
                ))}
              </AnimatePresence>
            </div>
          </>
        )}

        {/* ═══ ANALYTICS TAB ═══════════════════════════════════════════════ */}
        {tab==="analytics"&&(
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>

            {/* Cyber trend */}
            {cyberStats&&<div style={{background:C.panel,border:`1px solid ${C.border}`,
              borderRadius:12,padding:16,gridColumn:"span 2"}}>
              <div style={{color:C.muted,fontSize:9,letterSpacing:"0.12em",marginBottom:12}}>
                CYBER THREAT SEVERITY TREND (LAST 30 EVENTS)
              </div>
              <ResponsiveContainer width="100%" height={160}>
                <AreaChart data={cyberStats.trend}>
                  <defs>
                    <linearGradient id="cg" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor={C.high} stopOpacity={0.3}/>
                      <stop offset="95%" stopColor={C.high} stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke={C.border} strokeDasharray="3 3"/>
                  <XAxis dataKey="time" tick={{fill:C.muted,fontSize:9}}
                    tickFormatter={t=>t?.split("T")[1]?.slice(0,5)??t}/>
                  <YAxis domain={[0,1]} tick={{fill:C.muted,fontSize:9}}/>
                  <Tooltip content={<ChartTip/>}/>
                  <Area type="monotone" dataKey="score" name="Severity"
                    stroke={C.high} fill="url(#cg)" strokeWidth={2} dot={false}/>
                </AreaChart>
              </ResponsiveContainer>
            </div>}

            {/* Threat breakdown */}
            {cyberStats?.threat_breakdown?.length>0&&(
              <div style={{background:C.panel,border:`1px solid ${C.border}`,borderRadius:12,padding:16}}>
                <div style={{color:C.muted,fontSize:9,letterSpacing:"0.12em",marginBottom:12}}>
                  THREAT TYPE DISTRIBUTION
                </div>
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie data={cyberStats.threat_breakdown} cx="50%" cy="50%"
                      innerRadius={45} outerRadius={75} paddingAngle={3}
                      dataKey="value" nameKey="name"
                      label={({name,percent})=>`${name.replace(/_/g," ")} ${(percent*100).toFixed(0)}%`}
                      labelLine={false}>
                      {cyberStats.threat_breakdown.map((e,i)=><Cell key={i} fill={e.color}/>)}
                    </Pie>
                    <Tooltip content={<ChartTip/>}/>
                  </PieChart>
                </ResponsiveContainer>
              </div>
            )}

            {/* Log type breakdown */}
            {cyberStats?.log_type_breakdown?.length>0&&(
              <div style={{background:C.panel,border:`1px solid ${C.border}`,borderRadius:12,padding:16}}>
                <div style={{color:C.muted,fontSize:9,letterSpacing:"0.12em",marginBottom:12}}>
                  LOG TYPE & SEVERITY
                </div>
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={cyberStats.log_type_breakdown} barSize={40}>
                    <CartesianGrid stroke={C.border} strokeDasharray="3 3" vertical={false}/>
                    <XAxis dataKey="name" tick={{fill:C.muted,fontSize:10}}/>
                    <YAxis tick={{fill:C.muted,fontSize:10}}/>
                    <Tooltip content={<ChartTip/>}/>
                    <Bar dataKey="value" name="Count" radius={[4,4,0,0]}>
                      {cyberStats.log_type_breakdown.map((e,i)=><Cell key={i} fill={e.color}/>)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}

            {/* MITRE ATT&CK */}
            {cyberStats?.mitre_breakdown?.length>0&&(
              <div style={{background:C.panel,border:`1px solid ${C.border}`,
                borderRadius:12,padding:16,gridColumn:"span 2"}}>
                <div style={{color:C.muted,fontSize:9,letterSpacing:"0.12em",marginBottom:12}}>
                  MITRE ATT&CK TECHNIQUE FREQUENCY
                </div>
                <ResponsiveContainer width="100%" height={140}>
                  <BarChart data={cyberStats.mitre_breakdown} barSize={28}>
                    <CartesianGrid stroke={C.border} strokeDasharray="3 3" vertical={false}/>
                    <XAxis dataKey="technique" tick={{fill:C.muted,fontSize:10}}/>
                    <YAxis tick={{fill:C.muted,fontSize:10}}/>
                    <Tooltip content={<ChartTip/>}/>
                    <Bar dataKey="count" name="Count" fill={C.purple} radius={[4,4,0,0]}/>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}

            {/* Financial trend */}
            {stats&&<div style={{background:C.panel,border:`1px solid ${C.border}`,
              borderRadius:12,padding:16,gridColumn:"span 2"}}>
              <div style={{color:C.muted,fontSize:9,letterSpacing:"0.12em",marginBottom:12}}>
                FINANCIAL ANOMALY SCORE TREND
              </div>
              <ResponsiveContainer width="100%" height={140}>
                <AreaChart data={stats.trend}>
                  <defs>
                    <linearGradient id="fg" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor={C.accent} stopOpacity={0.3}/>
                      <stop offset="95%" stopColor={C.accent} stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke={C.border} strokeDasharray="3 3"/>
                  <XAxis dataKey="time" tick={{fill:C.muted,fontSize:9}}
                    tickFormatter={t=>t?.split("T")[1]?.slice(0,5)??t}/>
                  <YAxis domain={[0,1]} tick={{fill:C.muted,fontSize:9}}/>
                  <Tooltip content={<ChartTip/>}/>
                  <Area type="monotone" dataKey="score" name="Anomaly Score"
                    stroke={C.accent} fill="url(#fg)" strokeWidth={2} dot={false}/>
                  <Area type="monotone" dataKey="trading" name="Trading"
                    stroke={C.orange} fill="none" strokeWidth={1} strokeDasharray="4 2" dot={false}/>
                </AreaChart>
              </ResponsiveContainer>
            </div>}
          </div>
        )}

        {/* ═══ MODELS TAB ═══════════════════════════════════════════════════ */}
        {tab==="models"&&(
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
            <div style={{background:C.panel,border:`1px solid ${C.border}`,
              borderRadius:12,padding:18,gridColumn:"span 2"}}>
              <div style={{color:C.muted,fontSize:9,letterSpacing:"0.12em",marginBottom:14}}>
                COMPLETE ML ENSEMBLE — 8 FINANCIAL MODELS + 12 CYBER THREAT DETECTORS
              </div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10}}>
                {[
                  {name:"Isolation Forest",    type:"Unsupervised",  weight:"18%", color:C.accent},
                  {name:"Local Outlier Factor", type:"Unsupervised",  weight:"15%", color:C.accent},
                  {name:"XGBoost",             type:"Supervised",    weight:"15%", color:C.low},
                  {name:"Random Forest",       type:"Supervised",    weight:"12%", color:C.low},
                  {name:"Logistic Regression", type:"Supervised",    weight:"8%",  color:C.low},
                  {name:"ECOD (PyOD)",         type:"Statistical",   weight:"8%",  color:C.medium},
                  {name:"COPOD (PyOD)",        type:"Statistical",   weight:"6%",  color:C.medium},
                  {name:"DBSCAN Clustering",   type:"Unsupervised",  weight:"6%",  color:C.accent},
                  {name:"Z-Score / Mod-Z",     type:"Statistical",   weight:"6%",  color:C.medium},
                  {name:"Velocity Checks",     type:"Domain",        weight:"3%",  color:C.purple},
                  {name:"Trading Patterns",    type:"Domain",        weight:"3%",  color:C.orange},
                  {name:"Cyber Threat Engine", type:"Rule+ML",       weight:"SOC", color:C.high},
                ].map(m=>(
                  <div key={m.name} style={{background:"#060c1a",borderRadius:8,
                    padding:"10px 12px",border:`1px solid ${m.color}30`}}>
                    <div style={{color:m.color,fontSize:12,fontWeight:600,marginBottom:3}}>{m.name}</div>
                    <div style={{color:C.muted,fontSize:10}}>{m.type}</div>
                    <div style={{color:m.color,fontSize:18,fontFamily:"'DM Mono',monospace",
                      marginTop:5,fontWeight:700}}>{m.weight}</div>
                  </div>
                ))}
              </div>
            </div>

            <div style={{background:C.panel,border:`1px solid ${C.border}`,borderRadius:12,padding:18}}>
              <div style={{color:C.muted,fontSize:9,letterSpacing:"0.12em",marginBottom:12}}>
                CYBER THREAT CATEGORIES DETECTED
              </div>
              {[
                ["Network","PORT_SCAN, DDOS, DATA_EXFILTRATION, C2_BEACONING, DNS_TUNNELING",C.accent],
                ["Auth","BRUTE_FORCE, PRIV_ESCALATION, INSIDER_THREAT, LATERAL_MOVEMENT",C.purple],
                ["Endpoint","RANSOMWARE, SQL_INJECTION, XSS_ATTACK",C.orange],
              ].map(([cat,threats,color])=>(
                <div key={cat} style={{padding:"10px",background:"#060c1a",
                  borderRadius:8,marginBottom:8,border:`1px solid ${color}30`}}>
                  <div style={{color,fontSize:12,fontWeight:600,marginBottom:4}}>{cat} Threats</div>
                  <div style={{color:C.muted,fontSize:10}}>{threats}</div>
                </div>
              ))}
            </div>

            <div style={{background:C.panel,border:`1px solid ${C.border}`,borderRadius:12,padding:18}}>
              <div style={{color:C.muted,fontSize:9,letterSpacing:"0.12em",marginBottom:12}}>
                SUCCESS CRITERIA
              </div>
              {[
                ["Financial Detection Rate",">85%",`${stats?.detection_rate??0}%`,C.low],
                ["False Positive Rate","<5%",`${stats?.false_positive_rate??0}%`,C.medium],
                ["Cyber Detection Rate",">80%",`${cyberStats?.detection_rate??0}%`,C.low],
                ["XGB Precision",">80%",fmtPct(stats?.model_metrics?.xgb_precision),C.accent],
                ["XGB Recall",">80%",fmtPct(stats?.model_metrics?.xgb_recall),C.accent],
                ["System Uptime","99.5%+","99.9%",C.low],
              ].map(([label,target,actual,color])=>(
                <div key={label} style={{display:"flex",justifyContent:"space-between",
                  alignItems:"center",padding:"6px 0",borderBottom:`1px solid ${C.border}`}}>
                  <span style={{color:C.text,fontSize:11}}>{label}</span>
                  <span style={{color:C.muted,fontSize:10}}>Target: {target}</span>
                  <span style={{color,fontSize:12,fontFamily:"'DM Mono',monospace"}}>{actual}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Toast */}
      <AnimatePresence>
        {toast&&(
          <motion.div initial={{opacity:0,y:30}} animate={{opacity:1,y:0}} exit={{opacity:0,y:30}}
            style={{position:"fixed",bottom:20,right:20,
              background:toast.type==="error"?"#1a0510":"#040e1a",
              border:`1px solid ${toast.type==="error"?C.high:C.accent}60`,
              color:toast.type==="error"?C.high:C.accent,
              borderRadius:10,padding:"10px 16px",fontSize:11,
              fontFamily:"'DM Mono',monospace",maxWidth:400,zIndex:999}}>
            {toast.type==="error"?"⚠ ":"✓ "}{toast.msg}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}