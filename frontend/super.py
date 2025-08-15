from brian2 import *
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

# ===== PARÂMETROS GERAIS =====
N = 500
input_dim = 32
sim_dt = 0.1*ms
sim_time = 300*ms
defaultclock.dt = sim_dt

# ===== MODELO IZHICKEVICH COM PLASTICIDADE, EXCITABILIDADE E MODULAÇÕES =====
izh_eqs = '''
dv/dt = (0.04*v**2 + 5*v + 140 - u + I_syn + I_affect + I_quant)/ms : 1
du/dt = a*(b*v - u)/ms : 1

I_syn : 1
I_affect : 1       # Modulação afetiva
I_quant : 1        # Modulação quântica

a : 1
b : 1
c : 1
d : 1

plasticity_rate : 1
'''

# ===== REDE NEURONAL =====
neurons = NeuronGroup(N, model=izh_eqs, threshold='v>30', reset='v=c; u+=d', method='euler')
neurons.v = -65 + 15*np.random.rand(N)
neurons.a = 0.02
neurons.b = 0.2
neurons.c = -65
neurons.d = 8
neurons.u = neurons.b * neurons.v
neurons.plasticity_rate = 0.01
neurons.I_affect = 0
neurons.I_quant = 0
neurons.I_syn = 0

# ===== ENTRADA POISSON =====
poisson_input = PoissonGroup(input_dim, rates=0*Hz)

# ===== CONEXÕES ENTRADA → REDE COM STDP E METAPLASTICIDADE =====
tau_pre = 20*ms
tau_post = 20*ms
A_pre = 0.01
A_post = -A_pre * 1.05
w_max = 1.0

syn_eqs = '''
w : 1
dpre/dt = -pre / tau_pre : 1 (event-driven)
dpost/dt = -post / tau_post : 1 (event-driven)
'''

on_pre = '''
I_syn_post += w
pre = 1
w = clip(w + plasticity_rate_post * A_pre * post, 0, w_max)
'''

on_post = '''
post = 1
w = clip(w + plasticity_rate_pre * A_post * pre, 0, w_max)
'''

input_to_res = Synapses(poisson_input, neurons, model=syn_eqs, on_pre=on_pre, on_post=on_post)
input_to_res.connect(p=0.12)
input_to_res.w = '0.2 * rand()'

# ===== CONEXÕES RECORRENTES (fixas) =====
res_to_res = Synapses(neurons, neurons, on_pre='I_syn_post += 0.1', delay=1*ms)
res_to_res.connect(condition='i!=j', p=0.08)

# ===== HOMEOSTASE (regulação da excitabilidade para manter taxa-alvo) =====
@network_operation(dt=10*ms)
def homeostasis():
    target_rate = 5  # Hz
    rates = population_rate(neurons, dt=10*ms)
    error = target_rate - rates
    neurons.I_affect += 0.01 * error  # Afeto também modula excitabilidade

def population_rate(group, dt):
    spks = spikemon.spike_trains()
    rates = np.zeros(len(spks))
    for i, train in enumerate(spks):
        rates[i] = np.sum((train > defaultclock.t - dt) & (train <= defaultclock.t)) / (dt / second)
    return rates

# ===== MÓDULO METACOGNIÇÃO =====
class MetaCognition:
    def __init__(self, neuron_group):
        self.neurons = neuron_group
        self.rate_history = []
        self.plasticity_mod = 0.01
        self.exc_mod = 0.0

    def observe(self, current_time):
        spikes = spikemon.spike_trains()
        window = 20*ms
        rates = []
        for i in range(len(spikes)):
            count = np.sum((spikes[i] > (current_time - window)) & (spikes[i] <= current_time))
            rates.append(count / (window/second))
        mean_rate = np.mean(rates)
        self.rate_history.append(mean_rate)
        return mean_rate

    def adjust(self, current_time):
        mean_rate = self.observe(current_time)
        target_rate = 5.0
        error = target_rate - mean_rate

        self.plasticity_mod += 0.0001 * error
        self.plasticity_mod = np.clip(self.plasticity_mod, 0.001, 0.05)

        self.exc_mod += 0.001 * error
        self.exc_mod = np.clip(self.exc_mod, -1.0, 1.0)

        self.neurons.plasticity_rate = self.plasticity_mod
        self.neurons.I_affect += self.exc_mod

meta = MetaCognition(neurons)

@network_operation(dt=10*ms)
def meta_op():
    meta.adjust(defaultclock.t)

# ===== MÓDULO DE AFETO E MOTIVAÇÃO =====
class AffectModule:
    def __init__(self, neuron_group):
        self.neurons = neuron_group
        self.valence = 0.0
        self.arousal = 0.5

    def update(self):
        t = defaultclock.t/ms
        self.valence = np.sin(t/1000)
        self.arousal = 0.5 + 0.5 * np.cos(t/1500)

        self.neurons.I_affect += self.arousal * 0.5
        base_plasticity = 0.01
        self.neurons.plasticity_rate = base_plasticity * (1 + self.valence)

affect = AffectModule(neurons)

@network_operation(dt=10*ms)
def affect_op():
    affect.update()

# ===== MÓDULO QUÂNTICO ABSTRATO =====
class QuantumModule:
    def __init__(self, neuron_group):
        self.neurons = neuron_group
        self.noise_amplitude = 0.2

    def update(self):
        noise = np.random.normal(0, self.noise_amplitude, size=len(self.neurons))
        self.neurons.I_quant = noise

        plasticity_noise = np.random.normal(0, self.noise_amplitude*0.05, size=len(self.neurons))
        new_plasticity = self.neurons.plasticity_rate + plasticity_noise
        new_plasticity = np.clip(new_plasticity, 0.001, 0.05)
        self.neurons.plasticity_rate = new_plasticity

quantum_mod = QuantumModule(neurons)

@network_operation(dt=10*ms)
def quantum_op():
    quantum_mod.update()

# ===== MONITORES =====
spikemon = SpikeMonitor(neurons)
ratemon = PopulationRateMonitor(neurons)

# ===== VETORIZADOR PARA INPUT TEXTUAL =====
vectorizer = TfidfVectorizer(max_features=input_dim)
seed_corpus = ["ola como vai", "bom dia", "teste input", "inteligencia artificial"]
vectorizer.fit(seed_corpus)

def text_to_rates(text, base_rate=5.0, max_rate=80.0):
    vec = vectorizer.transform([text]).toarray().flatten()
    if vec.sum() == 0:
        vec = np.ones_like(vec) * 1e-6
    vec = vec / (vec.max() + 1e-9)
    rates = base_rate + vec * (max_rate - base_rate)
    if len(rates) < input_dim:
        rates = np.pad(rates, (0, input_dim - len(rates)), 'constant', constant_values=base_rate)
    return rates[:input_dim]

# ===== REDE E LOOP =====
net = Network(collect(), homeostasis, meta_op, affect_op, quantum_op)

print("Rede SNN integrada rodando. Digite frases para testar, ou 'sair' para encerrar.")

while True:
    inp = input("> ")
    if inp.strip().lower() == 'sair':
        break
    rates = text_to_rates(inp)
    poisson_input.rates = rates * Hz
    spikemon.clear()
    ratemon.rate_.resize(0)
    net.run(sim_time)
    print(f"Taxa média de disparo: {np.mean(ratemon.rate_):.2f} Hz")
