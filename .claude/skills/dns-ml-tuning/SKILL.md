---
name: dns-ml-tuning
description: |
  All Cheat Sheets — Machine Learning, Deep Learning, and Artificial
  Intelligence (Stanford CS229 Fall 2018 + CS230 Winter 2019 + CS221
  Spring 2019, by Shervine & Afshine Amidi; compiled by Nikhil Yadav).
  Full condensed reference of the source PDF, organized by its own
  table of contents. Load this whenever any task involves: supervised
  or unsupervised learning, neural networks (NN/CNN/RNN/LSTM/attention),
  reinforcement learning, probability/statistics refresher, linear
  algebra refresher, metrics (accuracy/precision/recall/F1/ROC/AUC/PR),
  regularization (LASSO/Ridge/Elastic Net/dropout/early stopping),
  cross-validation, hyperparameter tuning, feature engineering,
  bias-variance, loss functions, gradient descent / Adam / SGD, k-NN,
  SVM, Naive Bayes, decision trees, random forest, boosting, k-means,
  PCA, EM, autoencoders, data augmentation, batch normalization,
  weight initialization, transfer learning, object detection, YOLO,
  R-CNN, word embeddings, word2vec, GloVe, beam search, BLEU, GANs,
  ResNet, Inception, A* search, Markov decision processes, Q-learning,
  value iteration, Bayesian networks, constraint satisfaction, logic,
  or any ML/DL/AI concept the three courses cover. Also load it when
  the request is "cheat sheet", "formulas", "theory check", "which
  model/loss/metric", or when verifying textbook correctness of code
  under src/dns_detect/. Content follows the PDF's own ordering.
---

# All Cheat Sheets — ML, DL, AI (Stanford/Amidi, compiled 2018–2019)

Source document: `All_Cheat_Sheets_Machine_Learning,_Deep_Learning_and_Aritificial.pdf`.
This skill condenses the full PDF while preserving its structure. Section
numbers follow the PDF.

---

# PART A — CS 229: Machine Learning (Stanford, Fall 2018)

## 1. Supervised Learning

### 1.1 Introduction

Given {(x⁽ⁱ⁾, y⁽ⁱ⁾)} build a classifier learning y from x.

- **Prediction types**: regression (continuous y) vs classification (class y).
- **Model types**:
  - *Discriminative* — directly estimate P(y|x). Decision boundary. Examples: regressions, SVMs.
  - *Generative* — estimate P(x|y) then use Bayes. Probability distribution of data. Examples: GDA, Naive Bayes.

### 1.2 Notations & general concepts

- **Hypothesis** h: model. Prediction = h(x⁽ⁱ⁾).
- **Loss function** L(z, y): how far predicted z is from true y.
- **Common losses**:
  | Least-squared | Logistic | Hinge | Cross-entropy |
  |---|---|---|---|
  | ½(y−z)² | log(1+exp(−yz)) | max(0, 1−yz) | −[y log z + (1−y) log(1−z)] |
- **Cost function** J(θ) = Σᵢ L(h_θ(x⁽ⁱ⁾), y⁽ⁱ⁾).
- **Gradient descent**: θ ← θ − α ∇J(θ). SGD = per-example; batch = per-batch.
- **Likelihood** L(θ) — maximize log L(θ) = ℓ(θ).
- **Newton's algorithm**: θ ← θ − ℓ'(θ)/ℓ''(θ). Multidim: θ ← θ − (∇²ℓ)⁻¹ ∇ℓ.

### 1.3 Linear models

**1.3.1 Linear regression** — y|x; θ ~ N(μ, σ²).
- Normal equations: θ = (XᵀX)⁻¹Xᵀy.
- LMS/Widrow-Hoff rule: θⱼ ← θⱼ + α Σᵢ (y⁽ⁱ⁾ − h_θ(x⁽ⁱ⁾)) xⱼ⁽ⁱ⁾.
- LWR: locally weighted regression with w⁽ⁱ⁾(x) = exp(−(x⁽ⁱ⁾−x)² / 2τ²).

**1.3.2 Classification & logistic regression** — y|x; θ ~ Bernoulli(φ).
- Sigmoid: g(z) = 1/(1+e⁻ᶻ), range (0,1).
- Logistic: φ = P(y=1|x;θ) = g(θᵀx). No closed-form; use iterative methods.
- **Softmax regression** (multiclass): φᵢ = exp(θᵢᵀx) / Σⱼ exp(θⱼᵀx).

**1.3.3 Generalized linear models (GLMs)** — y|x;θ ~ ExpFamily(η); h(x) = E[y|x;θ]; η = θᵀx. OLS and logistic regression are special cases.

### 1.4 Support Vector Machines

- Goal: maximize minimum distance to the decision line.
- **Optimal margin classifier**: h(x) = sign(wᵀx − b). Solve: min ½‖w‖² s.t. y⁽ⁱ⁾(wᵀx⁽ⁱ⁾ − b) ≥ 1.
- **Hinge loss**: L(z,y) = max(0, 1 − yz).
- **Kernel**: K(x,z) = φ(x)ᵀφ(z). Gaussian kernel K(x,z) = exp(−‖x−z‖²/2σ²).
- **Kernel trick**: compute cost using only K(x,z), never need explicit φ.
- **Lagrangian**: L(w,b) = f(w) + Σ βᵢ hᵢ(w).

### 1.5 Generative learning

**1.5.1 GDA (Gaussian Discriminant Analysis)** — y ~ Bernoulli(φ); x|y=0 ~ N(μ₀, Σ); x|y=1 ~ N(μ₁, Σ). MLE estimates for φ, μⱼ, Σ.

**1.5.2 Naive Bayes** — assumes features independent given y: P(x|y) = Πᵢ P(xᵢ|y). MLE gives P(y=k) = (1/m)·#{j: y⁽ʲ⁾=k} and P(xᵢ=l|y=k) = #{j: y⁽ʲ⁾=k ∧ xᵢ⁽ʲ⁾=l} / #{j: y⁽ʲ⁾=k}. Widely used for text classification / spam.

### 1.6 Tree-based & ensemble methods

- **CART (decision tree)**: binary tree. Very interpretable.
- **Random Forest**: many trees on random feature subsets. Uninterpretable but strong. (Ensemble method.)
- **Boosting**: combine weak learners into a strong one.
  | AdaBoost | Gradient Boosting |
  |---|---|
  | High weights on errors to improve next step | Weak learners trained on remaining errors |

### 1.7 Non-parametric: k-NN

- Response of a point determined by its k neighbors. Classification + regression.
- Higher k → higher bias; lower k → higher variance.

### 1.8 Learning Theory

- **Union bound**: P(A₁∪…∪Aₖ) ≤ ΣP(Aᵢ).
- **Hoeffding**: P(|φ−φ̂|>γ) ≤ 2 exp(−2γ²m).
- **Training error** ε̂(h) = (1/m) Σ 1{h(x⁽ⁱ⁾)≠y⁽ⁱ⁾}.
- **PAC** framework: train+test same distribution; i.i.d. training examples.
- **Shattering**: H shatters S if H realizes every labeling of S.
- **Upper bound** (finite H, |H|=k): with prob ≥ 1−δ, ε(ĥ) ≤ min_{h∈H} ε(h) + 2√((1/2m) log(2k/δ)).
- **VC dimension**: size of largest set shattered by H. VC(2D linear classifiers) = 3.
- **Vapnik's theorem**: ε(ĥ) ≤ min ε(h) + O(√((d/m) log(m/d) + (1/m) log(1/δ))).

## 2. Unsupervised Learning

### 2.1 Introduction
Find hidden patterns in unlabeled data {x⁽¹⁾, …, x⁽ᵐ⁾}.
- **Jensen's inequality**: for convex f, E[f(X)] ≥ f(E[X]).

### 2.2 Clustering

**2.2.1 Expectation-Maximization (EM)**
- *Latent variables* z: hidden.
- *Settings*: Mixture of k Gaussians (z ~ Multinomial, x|z ~ N(μⱼ,Σⱼ)); Factor analysis (z ~ N(0,I), x|z ~ N(μ+Λz, ψ)).
- *E-step*: Qᵢ(z⁽ⁱ⁾) = P(z⁽ⁱ⁾|x⁽ⁱ⁾; θ).
- *M-step*: θ ← argmax_θ Σᵢ ∫ Qᵢ(z⁽ⁱ⁾) log(P(x⁽ⁱ⁾, z⁽ⁱ⁾; θ)/Qᵢ(z⁽ⁱ⁾)) dz⁽ⁱ⁾.

**2.2.2 k-means**
- Repeat: c⁽ⁱ⁾ = argmin_j ‖x⁽ⁱ⁾ − μⱼ‖²; μⱼ = Σᵢ 1{c⁽ⁱ⁾=j} x⁽ⁱ⁾ / Σᵢ 1{c⁽ⁱ⁾=j}.
- Distortion J(c, μ) = Σᵢ ‖x⁽ⁱ⁾ − μ_{c⁽ⁱ⁾}‖².

**2.2.3 Hierarchical clustering** — agglomerative; linkage types: Ward (within-cluster distance), Average (between-cluster average), Complete (between-cluster maximum).

**2.2.4 Clustering metrics**
- **Silhouette** s = (b−a)/max(a,b).
- **Calinski-Harabasz** s(k) = (Tr(Bₖ)/Tr(Wₖ)) · (N−k)/(k−1).

### 2.3 Dimension reduction

**2.3.1 PCA** — projects data onto variance-maximizing axes.
1. Normalize x⁽ⁱ⁾_j ← (x⁽ⁱ⁾_j − μⱼ)/σⱼ.
2. Σ = (1/m) Σᵢ x⁽ⁱ⁾ x⁽ⁱ⁾ᵀ.
3. Compute k largest eigenvectors u₁,…,uₖ.
4. Project onto span(u₁,…,uₖ).

**2.3.2 ICA (Independent Component Analysis)** — find unmixing W = A⁻¹ via Bell-Sejnowski algorithm with log-likelihood over sources.

## 3. Deep Learning

### 3.1 Neural Networks

- Each hidden unit: zⱼ⁽ⁱ⁾ = wⱼ⁽ⁱ⁾ᵀ x + bⱼ⁽ⁱ⁾.
- **Activation functions**:
  | Sigmoid | Tanh | ReLU | Leaky ReLU |
  |---|---|---|---|
  | 1/(1+e⁻ᶻ) | (eᶻ−e⁻ᶻ)/(eᶻ+e⁻ᶻ) | max(0, z) | max(εz, z), ε≪1 |
- **Cross-entropy loss**: L(z,y) = −[y log z + (1−y) log(1−z)].
- **Learning rate** α — adaptive methods (Adam) are standard.
- **Backprop** (chain rule): ∂L/∂w = (∂L/∂a)(∂a/∂z)(∂z/∂w). Update: w ← w − α ∂L/∂w.
- **Weight update sequence**: forward prop → compute loss → backprop → update.
- **Dropout** — randomly drop units with prob p to prevent overfit.

### 3.2 CNNs

- **Convolutional requirement**: N = ⌊(W − F + 2P)/S⌋ + 1 neurons fit.
- **Batch normalization**: xᵢ ← γ(xᵢ − μ_B)/√(σ²_B + ε) + β. Done after FC/conv, before non-linearity.

### 3.3 RNNs

- **Gates**: Input (write?), Forget (erase?), Output (reveal?), plus Gate (how much?).
- **LSTM** — RNN with forget gates to avoid vanishing gradient.

### 3.4 Reinforcement Learning

- **MDP**: (S, A, {P_sa}, γ, R).
- **Policy** π: S → A.
- **Value function** V^π(s) = E[R(s₀) + γR(s₁) + γ²R(s₂) + … | s₀=s, π].
- **Optimal Bellman**: V*(s) = R(s) + max_a γ Σ_{s'} P_sa(s') V*(s').
- **Optimal policy** π*(s) = argmax_a Σ P_sa(s') V*(s').
- **Value iteration**: Vᵢ₊₁(s) = R(s) + max_a γ Σ P_sa(s') Vᵢ(s'). Starts V₀(s)=0.
- **Max likelihood** P_sa(s') = #{took a in s, got s'} / #{took a in s}.
- **Q-learning**: Q(s,a) ← Q(s,a) + α [R(s,a,s') + γ max_{a'} Q(s',a') − Q(s,a)].

## 4. ML Tips & Tricks

### 4.1 Metrics

**4.1.1 Classification**

Confusion matrix: TP (true pos), FN (false neg), FP (false pos), TN (true neg).

| Metric | Formula |
|---|---|
| Accuracy | (TP+TN)/(TP+TN+FP+FN) |
| Precision | TP/(TP+FP) |
| Recall / Sensitivity / TPR | TP/(TP+FN) |
| Specificity | TN/(TN+FP) |
| F1 score | 2TP/(2TP+FP+FN) |
| FPR | FP/(TN+FP) |

- **ROC** = TPR vs FPR by varying threshold.
- **AUC / AUROC** = area under ROC.

**4.1.2 Regression**

- SS_tot = Σ(yᵢ − ȳ)²; SS_reg = Σ(f(xᵢ) − ȳ)²; SS_res = Σ(yᵢ − f(xᵢ))².
- **R²** = 1 − SS_res / SS_tot.
- **Mallow's Cₚ** = (SS_res + 2(n+1)σ̂²)/m.
- **AIC** = 2(n+2) − 2 log L.
- **BIC** = log(m)(n+2) − 2 log L.
- **Adjusted R²** = 1 − (1−R²)(m−1)/(m−n−1).

### 4.2 Model selection

- **Vocabulary**: training (model trained, ~80%), validation (model assessed, ~20%, aka hold-out/dev), testing (unseen).
- **Cross-validation**:
  | k-fold | Leave-p-out |
  |---|---|
  | Train on k−1 folds, test on remaining; k=5 or 10 | Train on n−p, test on p; p=1 is leave-one-out |
- **Regularization** (fights high variance):
  | LASSO | Ridge | Elastic Net |
  |---|---|---|
  | Shrinks coefs to 0; good for feature selection | Makes coefs smaller | Tradeoff between selection & shrinkage |
  | …+λ‖θ‖₁ | …+λ‖θ‖₂² | …+λ(α(1−α)‖θ‖₁ + α‖θ‖₂²) |

### 4.3 Diagnostics

- **Bias**: expected prediction − true. **Variance**: variability of prediction across samples.
- **Bias/variance tradeoff**: simpler model → higher bias; more complex → higher variance.

| Symptoms | Underfitting | Just right | Overfitting |
|---|---|---|---|
| Training error | high | slightly lower than test | much lower than test |
| Test error | ≈ training | ≈ training | ≫ training |
| Diagnosis | high bias | — | high variance |
| Remedies | Complexify / add features / train longer | — | Regularize / more data |

- **Error analysis** — root cause of current-vs-perfect gap.
- **Ablative analysis** — root cause of current-vs-baseline gap.

## 5. Refreshers

### 5.1 Probability & Statistics

**5.1.1 Intro / Combinatorics**
- Sample space S, event E ⊆ S.
- Axioms: 0 ≤ P(E) ≤ 1; P(S) = 1; mutually exclusive events sum.
- **Permutations**: P(n,r) = n!/(n−r)!
- **Combinations**: C(n,r) = n!/(r!(n−r)!)

**5.1.2 Conditional probability**
- **Bayes**: P(A|B) = P(B|A)P(A)/P(B).
- **Partition** {Aᵢ}: Aᵢ∩Aⱼ=∅, ∪Aᵢ=S.
- **Total probability**: P(B) = Σᵢ P(B|Aᵢ)P(Aᵢ).
- **Extended Bayes**: P(Aₖ|B) = P(B|Aₖ)P(Aₖ) / Σᵢ P(B|Aᵢ)P(Aᵢ).
- **Independence**: P(A∩B) = P(A)P(B).

**5.1.3 Random variables**
- **CDF** F(x) = P(X≤x).
- **PDF** f (continuous) / PMF f(xⱼ) = P(X=xⱼ) (discrete).
- **Expectation**: E[X] = Σ xᵢ f(xᵢ) or ∫ x f(x) dx.
- **Variance**: Var(X) = E[(X−E[X])²] = E[X²] − E[X]².
- **Chebyshev**: P(|X−μ| ≥ kσ) ≤ 1/k².

**5.1.4 Jointly distributed**
- Conditional density: f_{X|Y}(x) = f_{XY}(x,y)/f_Y(y).
- Independence: f_{XY} = f_X · f_Y.
- **Covariance**: Cov(X,Y) = E[XY] − μ_X μ_Y.
- **Correlation**: ρ_{XY} = Cov(X,Y)/(σ_X σ_Y) ∈ [−1, 1].
- **Main distributions**: Binomial, Poisson, Uniform, Gaussian, Exponential.

**5.1.5 Parameter estimation**
- **Random sample** X₁…Xₙ i.i.d.
- **Estimator** θ̂ = f(data).
- **Bias**: E[θ̂] − θ; unbiased ⇔ E[θ̂] = θ.
- **Sample mean** X̄ = (1/n) Σ Xᵢ.
- **Sample variance** s² = (1/(n−1)) Σ (Xᵢ − X̄)².
- **CLT**: X̄ → N(μ, σ²/n) as n → ∞.

### 5.2 Linear Algebra & Calculus

**5.2.1 Notations**
- Vector x ∈ ℝⁿ; matrix A ∈ ℝ^{m×n}; identity I; diagonal diag(d₁,…,dₙ).

**5.2.2 Matrix operations**
- Inner product xᵀy ∈ ℝ; outer product xyᵀ ∈ ℝ^{m×n}.
- Matrix-vector / matrix-matrix products.
- Transpose Aᵀ with (AB)ᵀ = BᵀAᵀ.
- Inverse A⁻¹: AA⁻¹ = I. (AB)⁻¹ = B⁻¹A⁻¹.
- Trace tr(A) = Σ Aᵢᵢ. tr(AB) = tr(BA).
- Determinant det(A) = Σⱼ (−1)^{i+j} Aᵢⱼ |A_{\i\j}|.

**5.2.3 Matrix properties**
- Symmetric decomposition: A = (A+Aᵀ)/2 + (A−Aᵀ)/2.
- **Norms**:
  | Norm | Definition | Use |
  |---|---|---|
  | L¹ | Σ|xᵢ| | LASSO |
  | L² | √Σxᵢ² | Ridge |
  | Lᵖ | (Σ|xᵢ|ᵖ)^{1/p} | Hölder |
  | L^∞ | max |xᵢ| | uniform convergence |
- Linear independence, matrix rank.
- **PSD**: A = Aᵀ and xᵀAx ≥ 0 ∀x. Positive definite: xᵀAx > 0.
- **Eigenvalue** λ, eigenvector z: Az = λz.
- **Spectral theorem**: symmetric A diagonalizable by orthogonal U: A = UΛUᵀ.

**5.2.4 Matrix calculus**
- Gradient ∇_A f(A): (∇_A f)ᵢⱼ = ∂f/∂Aᵢⱼ.
- Hessian ∇²_x f(x): symmetric n×n.
- Gradient identities: ∇_A tr(AB) = Bᵀ; ∇_A f(A)ᵀ = (∇_A f(A))ᵀ; ∇_A tr(ABAᵀC) = CAB + CᵀABᵀ; ∇_A |A| = |A|(A⁻¹)ᵀ.

---

# PART B — CS 230: Deep Learning (Stanford, Winter 2019)

## 1. Convolutional Neural Networks

### 1.1 Overview
Layers: CONV, POOL, FC, activation.

### 1.2 Types of layer
- **CONV** — filters of size F×F×C scan input I×I×C via stride S, producing feature map O×O×K.
- **POOL** — downsampling. Max (preserve features, most common) vs Average (used in LeNet).
- **FC** — flat input, every input connected to every neuron. Usually last layer.

### 1.3 Filter hyperparameters
- **Filter dim**: F×F×C.
- **Stride** S: pixels moved per op.
- **Zero-padding** P modes: Valid (P=0), Same (output = ceil(I/S)), Full.
- Output size: O = (I − F + P_start + P_end)/S + 1.

### 1.4 Tuning hyperparameters

| Layer | Input | Output | #Params | Note |
|---|---|---|---|---|
| CONV | I×I×C | O×O×K | (F·F·C + 1)·K | S<F usually |
| POOL | I×I×C | O×O×C | 0 | S=F usually |
| FC | N_in | N_out | (N_in+1)·N_out | — |

- **Receptive field** at layer k: Rₖ = 1 + Σⱼ₌₁ᵏ (Fⱼ − 1) Πᵢ₌₀^{j−1} Sᵢ.

### 1.5 Activation functions
- **ReLU** max(0, z) — standard.
- **Leaky ReLU** max(εz, z) — fixes dying ReLU.
- **ELU** max(α(eᶻ−1), z) — differentiable everywhere.
- **Softmax** pᵢ = exp(xᵢ)/Σⱼ exp(xⱼ) — classifier head.

### 1.6 Object detection

- **Types**: image classification → classification+localization → detection.
- **Bounding box**: (bₓ, bᵧ, bₕ, b_w); landmark: list of (lᵢₓ, lᵢᵧ).
- **IoU** = |Bₚ ∩ Bₐ| / |Bₚ ∪ Bₐ|; good if ≥ 0.5.
- **Anchor boxes** — predict multiple boxes with different geometries per cell.
- **Non-max suppression**: drop boxes with p<0.6; repeat {pick top-prob, drop IoU≥0.5 overlaps}.
- **YOLO**: grid G×G; per cell predict y = [p_c, bₓ, bᵧ, bₕ, b_w, c₁…c_p] × k anchors; then non-max suppression.
- **R-CNN**: segment to get candidate boxes, then classify each. Fast/Faster R-CNN speed it up.

**1.6.1 Face verification/recognition**
- **Verification**: 1-to-1, "is this the right person?".
- **Recognition**: 1-to-K lookup.
- **One-shot learning**: learn similarity d(img1, img2).
- **Siamese network** — learn encoding f(x⁽ⁱ⁾).
- **Triplet loss** ℓ(A,P,N) = max(d(A,P) − d(A,N) + α, 0).

**1.6.2 Neural style transfer**
- **Content cost** J_content(C,G) = ½‖a[l](C) − a[l](G)‖².
- **Style matrix** G^{[l]} — Gram matrix of activations.
- **Style cost** J_style = (1/(2·n_H·n_w·n_c)²) ‖G^{[l](S)} − G^{[l](G)}‖_F².
- **Overall**: J(G) = α J_content + β J_style.

**1.6.3 Computational tricks**
- **GAN**: generator vs discriminator. Use cases: text-to-image, music gen.
- **ResNet**: residual blocks a^{[l+2]} = g(a^{[l]} + z^{[l+2]}).
- **Inception**: tries different conv sizes in parallel; uses 1×1 trick.

## 2. Recurrent Neural Networks

### 2.1 Overview
- a^{<t>} = g₁(W_aa·a^{<t−1>} + W_ax·x^{<t>} + b_a); y^{<t>} = g₂(W_ya·a^{<t>} + b_y).
- Pros: arbitrary input length, shared weights, uses history.
- Cons: slow, hard to access long-ago info, no future context.
- **Types**: one-to-one (traditional), one-to-many (music gen), many-to-one (sentiment), many-to-many (NER, MT).
- **Loss**: L(y, ŷ) = Σ_t L(y^{<t>}, ŷ^{<t>}).
- **BPTT**: ∂L^{(T)}/∂W = Σ_t ∂L^{(t)}/∂W.

### 2.2 Long-term dependencies
- **Activations**: sigmoid, tanh, ReLU.
- **Vanishing/exploding gradient**: fix via **gradient clipping** (cap max gradient).
- **Gates** Γ = σ(Wx^{<t>} + Ua^{<t−1>} + b):
  | Gate | Role |
  |---|---|
  | Update Γᵤ | How much past matters now? (GRU, LSTM) |
  | Relevance Γᵣ | Drop previous info? (GRU, LSTM) |
  | Forget Γ_f | Erase cell? (LSTM) |
  | Output Γₒ | Reveal cell? (LSTM) |
- **GRU vs LSTM**:
  - GRU: c̃^{<t>} = tanh(W_c[Γᵣ∗a^{<t−1>}, x^{<t>}] + b_c); c^{<t>} = Γᵤ∗c̃ + (1−Γᵤ)∗c^{<t−1>}.
  - LSTM: adds Γ_f gate on previous c, Γₒ gate on output.
- **BRNN** (bidirectional) and **DRNN** (deep RNN) are standard variants.

### 2.3 Word representation

**2.3.1 Motivation**
- 1-hot (oᵤ) vs word embedding (eᵤ).
- **Embedding matrix** E: eᵤ = E·oᵤ.

**2.3.2 Word embeddings**
- **Word2vec**: skip-gram, negative sampling, CBOW.
- **Skip-gram**: P(t|c) = exp(θ_tᵀ e_c) / Σⱼ exp(θⱼᵀ e_c).
- **Negative sampling**: binary logistic; k negative + 1 positive per step. Cheaper.
- **GloVe**: J(θ) = ½ Σᵢⱼ f(Xᵢⱼ)(θᵢᵀeⱼ + bᵢ + bⱼ − log Xᵢⱼ)².

### 2.4 Comparing words
- **Cosine similarity** = (w₁·w₂)/(‖w₁‖‖w₂‖).
- **t-SNE**: dim reduction for visualization.

### 2.5 Language model
- Estimate P(y). **n-gram** = count-based; **perplexity** PP = (Π_t 1/P̂)^{1/T}; lower is better.

### 2.6 Machine translation
- Encoder-decoder. Find ŷ = argmax P(y|x).
- **Beam search** of width B: keep top-B hypotheses.
- **Length normalization**: 1/T^α · Σ log P(y^{<t>} | …), α ∈ [0.5, 1].
- Error analysis: compare P(y*|x) vs P(ŷ|x) to blame beam vs RNN.
- **BLEU** = exp((1/n) Σₖ log pₖ), p_n = clipped n-gram counts. Add brevity penalty.

### 2.7 Attention
- α^{<t,t'>} = exp(e^{<t,t'>}) / Σ exp(e^{<t,t''>}).
- c^{<t>} = Σ_{t'} α^{<t,t'>} a^{<t'>}.
- Quadratic in T_x.

## 3. Deep Learning Tips & Tricks

### 3.1 Data processing
- **Augmentation** (images): flip, rotate, random crop, color shift, noise, info loss, contrast.
- **Batch normalization**: xᵢ ← γ(xᵢ−μ_B)/√(σ²_B+ε) + β. After FC/CONV, before non-linearity. Allows higher LR, less init sensitivity.

### 3.2 Training

**3.2.1 Definitions**
- **Epoch** = one pass over training set.
- **Mini-batch GD** = tunable batch; sweet spot between SGD noise and BGD slowness.
- **Loss function** L(z,y).
- **Cross-entropy** L = −[y log z + (1−y) log(1−z)].

**3.2.2 Finding optimal weights**
- **Backprop** via chain rule → gradients → w ← w − α ∂L/∂w.
- **Weight update** sequence: forward → loss → backprop gradients → weight step.

### 3.3 Parameter tuning

**3.3.1 Weights initialization**
- **Xavier**: tailors init to architecture (not purely random).
- **Transfer learning** by data size:
  | Data | Strategy |
  |---|---|
  | Small | Freeze all layers, train softmax only |
  | Medium | Freeze most layers, train last layers + softmax |
  | Large | Train everything, initializing from pre-trained |

**3.3.2 Optimizing convergence**
- **Learning rate** α — Adam adapts it.
- **Methods**:
  | Method | Notes | w update | b update |
  |---|---|---|---|
  | Momentum | Dampens oscillations | w − αv_{dw} | b − αv_{db} |
  | RMSprop | Root-mean-square; speeds learning | w − α dw/√s_{dw} | b − α db/√s_{db} |
  | Adam | Adaptive moment estimation; most popular; 4 params | w − α v_{dw}/(√s_{dw}+ε) | b − α v_{db}/(√s_{db}+ε) |
- Also: Adadelta, Adagrad, SGD.

### 3.4 Regularization
- **Dropout**: drop units with prob p (frameworks use "keep" = 1−p).
- **Weight regularization**: LASSO/Ridge/Elastic Net (same table as §4.2 above).
- **Early stopping**: stop when val loss plateaus/climbs.

### 3.5 Good practices
- **Overfit a small batch** first — if model can't memorize 20 examples, something is wrong.
- **Gradient checking**: numerical (f(x+h)−f(x−h))/2h vs analytical; sanity-check backprop. Choose h not too small (numerical instability) nor too large (poor approx).

---

# PART C — CS 221: Artificial Intelligence (Stanford, Spring 2019)

## 1. Reflex-based models

### 1.1 Linear predictors
- **Feature vector** φ(x) ∈ ℝ^d.
- **Score** s(x,w) = w·φ(x).
- **Linear classifier** f_w(x) = sign(s(x,w)).
- **Margin** m(x,y,w) = s(x,w)·y.
- **Linear regression**: f_w(x) = s(x,w). **Residual**: res = f_w(x) − y.

### 1.2 Loss minimization
- **Classification losses** (m = margin):
  | Zero-one | Hinge | Logistic |
  |---|---|---|
  | 1{m ≤ 0} | max(1 − m, 0) | log(1 + e⁻ᵐ) |
- **Regression losses**:
  | Squared | Absolute |
  |---|---|
  | res² | |res| |
- **TrainLoss** = (1/|D|) Σ Loss(x,y,w).

### 1.3 Non-linear predictors
- **k-NN** — non-parametric. Higher k → more bias; lower k → more variance.
- **Neural networks** — layers of z_j^{[i]} = w^{[i]T}_j x + b^{[i]}_j.

### 1.4 Stochastic gradient descent
- **GD**: w ← w − α ∇_w Loss(x,y,w).
- **SGD**: update per example (noisy, fast).
- **BGD**: update per batch (stable, slow).

### 1.5 Fine-tuning
- **Hypothesis class** F = {f_w : w ∈ ℝ^d}.
- **Logistic** σ(z) = 1/(1+e⁻ᶻ); σ'(z) = σ(z)(1−σ(z)).
- **Approximation error** ε_approx: F ↔ true g. **Estimation error** ε_est: f̂ ↔ best f* ∈ F.
- **Regularization** (same LASSO/Ridge/Elastic Net table).
- **Hyperparameters**: features, λ, iterations T, step size α.
- **Sets**: train (80%, model trained), validation (20%, model assessed, aka hold-out/dev), test (unseen).

### 1.6 Unsupervised

**1.6.1 k-means**
- Objective: Σᵢ ‖φ(xᵢ) − μ_{zᵢ}‖².
- Alternates: zᵢ = argmin_j ‖φ(xᵢ) − μⱼ‖²; μⱼ = (Σᵢ 1{zᵢ=j} φ(xᵢ)) / (Σᵢ 1{zᵢ=j}).

**1.6.2 PCA**
- Eigenvalue λ, eigenvector z: Az = λz.
- Spectral theorem: symmetric A = UΛUᵀ.
- Procedure: normalize → covariance → top-k eigenvectors → project.

## 2. States-based models

### 2.1 Search optimization

**2.1.1 Tree search** — explores all states+actions. Memory efficient, exponential time.

A **search problem**: start s_start, Actions(s), Cost(s,a), Succ(s,a), IsEnd(s).

- **Backtracking** — tries all possibilities.
- **BFS** — level order via queue (assume Cost(s,a) ≥ c).
- **DFS** — depth via stack (assume Cost=0).
- **Iterative deepening** — DFS to limited depth, raise.

| Algorithm | Cost | Space | Time |
|---|---|---|---|
| Backtracking | any | O(D) | O(b^D) |
| BFS | ≥c | O(b^d) | O(b^d) |
| DFS | 0 | O(D) | O(b^D) |
| DFS iter deepening | ≥c | O(d) | O(b^d) |

**2.1.2 Graph search** — DP + UCS.
- **DP** FutureCost(s) = 0 if IsEnd else min_a Cost(s,a) + FutureCost(Succ(s,a)). Acyclic only.
- **UCS** — explore in increasing PastCost(s). Equivalent to Dijkstra. Needs non-negative costs.

**2.1.3 Learning costs** — update weights to decrease training-path cost, increase predicted-path cost.

**2.1.4 A\* search**
- **Heuristic** h(s) ≈ FutureCost(s).
- Explore in increasing PastCost(s) + h(s). Equivalent to UCS with Cost'(s,a) = Cost(s,a) + h(Succ(s,a)) − h(s).
- **Consistency**: h(s_end) = 0 and h(s) ≤ Cost(s,a) + h(Succ(s,a)).

**2.1.5 Relaxation** — simpler problem to compute h.

### 2.2 Markov decision processes

**2.2.1** State s, action a, probabilities P(s'|s,a), reward Reward(s,a,s'), discount γ ∈ [0,1), policy π.

- **Utility**: u = Σ γ^t·r_t.
- **Q^π(s,a)** = expected utility of a then π.
- **V^π(s)** = expected utility starting at s.
- **Bellman**: Q^π(s,a) = Σ_{s'} P(s'|s,a)[Reward + γ V^π(s')].
- **Policy evaluation / iteration**.

**2.2.2 Applications**
- **Value iteration** — iterate V_opt until convergence.

**2.2.3 Unknown transitions/rewards**
- **Model-based MC**: estimate P̂, R̂ from samples, run value iteration.
- **Model-free MC**: Q̂^π(s,a) ← average observed utility.
- **SARSA**: Q̂^π(s,a) ← (1−η) Q̂^π + η (r + γ Q̂^π(s',a')).
- **Q-learning**: Q̂^opt(s,a) ← (1−η) Q̂^opt + η (r + γ max_{a'} Q̂^opt(s',a')).
- **ε-greedy** exploration.

### 2.3 Game playing
- **Minimax** V(s,a) = max_a min_{a'} V(Succ(s,a), a').
- **Alpha-beta pruning** — skip subtrees that can't change the decision.
- **Simultaneous games** — mixed strategies, Nash equilibrium.
- **Non-zero-sum** — multiple utilities, cooperation possible.

## 3. Variables-based models

### 3.1 Constraint satisfaction problems (CSPs)

**3.1.1 Factor graphs** — variables X₁…Xₙ, factors (constraints) fⱼ. Assignment weight = Π fⱼ.

**3.1.2 Dynamic ordering**
- **Backtracking search** with lookahead.
- **Most constrained variable** / **least constrained value** heuristics.
- **Forward checking** / **AC-3**.

**3.1.3 Approximate methods**
- **Beam search** of size K.
- **Local search** / **Gibbs sampling**.
- **Iterated conditional modes (ICM)**.

**3.1.4 Factor graph transformations** — handle special structure (independence, conditioning, Markov blanket).

### 3.2 Bayesian networks

**3.2.1 Introduction** — DAG with CPTs: P(X₁,…,Xₙ) = Πᵢ P(Xᵢ | parents(Xᵢ)).

**3.2.2 Probabilistic programs** — procedural specification of a joint.

**3.2.3 Inference** — enumeration / variable elimination / sampling (likelihood weighting, Gibbs).

## 4. Logic-based models

### 4.1 Basics — propositional vs first-order logic.
### 4.2 Knowledge base — set of formulas; **tell/ask**; **model checking** vs **theorem proving**.
### 4.3 Propositional logic — connectives ¬, ∧, ∨, →, ↔. Modus ponens; resolution.
### 4.4 First-order logic — predicates, quantifiers ∀, ∃. Unification; forward/backward chaining.

---

# PART D — Project-local reminders (DNS tunnel detection)

When applying the above to `src/dns_detect/`:

- **Path A** uses §1.6 (Random Forest + Boosting ensemble); add soft-vote per §1.6 Boosting; threshold per §4.1 F1-max on PR curve.
- **Path B** is a reconstruction autoencoder — not in the PDF, but transfers from §3 NN rules: MSE loss, Adam optimizer, early stopping (CS230 §3.4), dropout (CS230 §3.4), batch normalization (CS230 §1.4/§3.1).
- **Imbalanced classes** → prefer PR-AUC over accuracy (§4.1); report prevalence baseline.
- **Splits** → §4.2 train/val/test; k-fold CV when single split is noisy.
- **Regularization order** (CS229 §4.2 + CS230 §3.4): early stopping → dropout → L2 → L1 → Elastic Net.
- **Bias/variance diagnosis** → §4.3 table.
- **Metric fairness** → report full confusion matrix + precision + recall + F1 + ROC + PR.
- **Transfer learning** (CS230 §3.3) could apply if a pre-trained DNS/tunnel model becomes available.

Project docs that supply the DNS-specific context on top of this cheat sheet:
`docs/MODEL_EVALUATION_2026-10-24.md`, `docs/ML_IMPROVEMENTS.md`,
`docs/AUDIT_REPORT.md`, `docs/progress.md`, `docs/week1/PLAN.yaml`.

---

Sources: Shervine & Afshine Amidi — Stanford CS229 (Fall 2018), CS230 (Winter 2019),
CS221 (Spring 2019). Compiled by Nikhil Yadav. Full PDF text at
`C:\Users\ASUS\AppData\Local\Temp\claude\c--Programming-CTF-Capstone\40da2095-f717-4fa9-bda2-2f2902f42a97\scratchpad\cheatsheets.txt`.
