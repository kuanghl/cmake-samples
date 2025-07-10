# 格和对偶格生成
import numpy as np
from fpylll import IntegerMatrix, LLL
from sympy import Matrix

def generate_q_ary_lattice(q, n, m):
    # 生成n x m维矩阵
    A = np.random.randint(0, q, (n, m))
    lattice_points = []
    
    # 生成 n 维随机向量 s（系数向量）
    for _ in range(100):                            # 生成 100 个格点示例
        s = np.random.randint(0, 2, size=(1, m))    # 输入x ∈ {0,1}^m 随机列向量 (1 x m)
        y = (A @ s.T) % q                           # A: (n x m), s.T: (m x 1) → y: (n x 1),单向函数(OWF), f_A(x)=A*x mod q
        lattice_points.append(y.flatten())          # 展平为向量
        
    # 构造对偶格（需整数解，非实数解）
    # 需用整数线性代数库（如 sympy）求解 Ax ≡ 0 mod q
    A_mod = Matrix(A) % q
    null_space = A_mod.nullspace()  # 整数解基
    dual_basis = np.array(null_space).astype(int).squeeze()
    return lattice_points, dual_basis

# 示例
q = 17          # 模数
n, m = 5, 10     # 矩阵维度
lattice, dual_lattice = generate_q_ary_lattice(q, n, m)

print(lattice)
print("\n\n")
print(dual_lattice)