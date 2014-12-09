import glob
import os
import shutil
import subprocess
import sys
import time

script_dir = os.path.dirname(os.path.realpath(__file__))
working_dir = os.getcwd()
petuum_dir = os.path.join(script_dir, '..')
results_dir = os.path.join(petuum_dir, 'results', 'lda')
data_dir = os.path.join(petuum_dir, 'data')
app_dir = os.path.join(petuum_dir, 'apps', 'lda')

app_script_path = os.path.join(app_dir, 'scripts', 'run_lda.sh')
gen_script_path = os.path.join(app_dir, 'bin', 'data_preprocessor')
data_path = os.path.join(data_dir, 'lda_data')
hostfile_path = os.path.join(petuum_dir, 'hostfile')
raw_data_path = os.path.join(petuum_dir, 'nytimes', 'nytimes.dat')

ssp_params = [0, 1, 2, 4, 8, 16]

print 'Making data for LDA...'

try:
  os.makedirs(data_dir)
except:
  pass

subprocess.call([
  gen_script_path,
  raw_data_path,
  data_path,
  8,
])

try:
  os.makedirs(results_dir)
except:
  pass

for ssp in ssp_params:
  res_dir = os.path.join(results_dir, 'ssp_%d' % ssp)
  stats_path = os.path.join(res_dir, 'stats')

  try:
    shutil.rmtree(res_dir)
  except:
    pass

  try:
    os.makedirs(res_dir)
  except:
    pass
  
  subprocess.call([
    app_script_path,
    data_path,
    os.path.join(res_dir, 'output'),
    hostfile_path,
    str(ssp),
  ])

  while True:
    if glob.glob(os.path.join(res_dir, 'stats.*')):
      break
    time.sleep(1)
