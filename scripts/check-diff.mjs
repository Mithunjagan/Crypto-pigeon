import {spawnSync} from 'node:child_process';
const probe=spawnSync('git',['rev-parse','--is-inside-work-tree'],{encoding:'utf8',windowsHide:true});
if(probe.status!==0){console.log('Source archive: no Git metadata; build and tests remain the verification gates.');}
else {const result=spawnSync('git',['diff','--check'],{stdio:'inherit',windowsHide:true});process.exitCode=result.status??1;}
