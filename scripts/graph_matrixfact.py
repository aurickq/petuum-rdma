import glob
import os
import yaml

script_dir = os.path.dirname(os.path.realpath(__file__))
working_dir = os.getcwd()
petuum_dir = os.path.join(script_dir, '..')
results_dir = os.path.join(petuum_dir, 'results', 'matrixfact')
graphs_dir = os.path.join(petuum_dir, 'graphs', 'matrixfact')

ssp_dirs = glob.glob(os.path.join(results_dir, '*'))
for ssp_dir in ssp_dirs:
  ssp = int(os.path.basename(ssp_dir)[4:])
  stats_files = glob.glob(os.path.join(ssp_dir, 'stats.[0123456789]'))
  compute_time = 0.0
  for stats_file in stats_files:
    with open(stats_file, 'r') as f:
      docs = list(yaml.load_all(f))
    app_thread_life_sec = docs[1]['app_thread_life_sec']
    compute_time = max(compute_time, max(app_thread_life_sec[:-1]))
  print ssp, compute_time
