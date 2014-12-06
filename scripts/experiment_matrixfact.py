import glob
import os
import shutil
import subprocess
import sys
import time

script_dir = os.path.dirname(os.path.realpath(__file__))
working_dir = os.getcwd()
petuum_dir = os.path.join(script_dir, '..')
results_dir = os.path.join(petuum_dir, 'results', 'matrixfact')
data_dir = os.path.join(petuum_dir, 'data')
app_dir = os.path.join(petuum_dir, 'apps', 'matrixfact')

app_bin_path = os.path.join(app_dir, 'bin', 'matrixfact')
app_script_path = os.path.join(app_dir, 'scripts', 'run_matrixfact.sh')
gen_script_path = os.path.join(app_dir, 'sampledata', 'make_synth_data.py')
data_path = os.path.join(data_dir, 'matrixfact_data')
hostfile_path = os.path.join(petuum_dir, 'hostfile')

ssp_params = [0, 1, 2, 4, 8, 16]

print 'Making data for matrixfact...'

try:
  os.makedirs(data_dir)
except:
  pass

subprocess.call([
  'python',
  gen_script_path,
  str(100),                   # block-width
  str(50),                   # num-diag-blocks
  str(0.1),                  # off-diag-density
  data_path,
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
  
  args = [
    '--staleness %d' % ssp,
    '--ps_stats_path %s' % stats_path,
  ]

  subprocess.call([
    app_script_path,
    data_path,
    str(30),            # K
    str(100),           # iters
    os.path.join(res_dir, 'output'),
    hostfile_path,
    str(16),            # client_worker_threads
    '%s' % ' '.join(args),
  ])

  while True:
    if glob.glob(os.path.join(res_dir, 'stats.*')):
      break
    time.sleep(1)
