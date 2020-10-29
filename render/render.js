#!/usr/bin/env node

// quick and dirty.  exceptions crash the script.

const fs = require('fs')
const ejs = require('ejs')
const yaml = require('js-yaml')
const marked = require('marked')
 
if(process.argv.length !== 4){
  console.log(`incorrect number of arguments\nusage: ${process.argv[1]} [ejs-file] [yaml-file]`)
  process.exit(1)
}

let data = yaml.safeLoad(fs.readFileSync(process.argv[3], 'utf8'))
data.marked = marked

const template = ejs.compile(fs.readFileSync(process.argv[2], 'utf8'))
process.stdout.write(template(data))
