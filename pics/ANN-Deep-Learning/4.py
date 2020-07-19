import matplotlib.pyplot as plt
import numpy as np
x = np.linspace(0.0, 10.0, 100)
y1 = 4 * x - 2
y2 = 1.2 * x + 2
y3 = -0.3 * x + 8
y4 = np.minimum(y1, y3)
plt.plot(x, y1)
plt.plot(x, y2)
plt.plot(x, y3)
plt.fill_between(x, y4, y2, where=y4>y2, color='grey', alpha=0.5)
y1 = 0.2 * x
y2 = -0.2 * x + 2
y3 = -10 * x + 80
y4 = np.minimum(y1, y3)
plt.fill_between(x, y4, y2, where=y4>y2, color='grey', alpha=0.5)
plt.plot(x, y1)
plt.plot(x, y2)
plt.plot(x, y3)
plt.xlabel('x1')
plt.ylabel('x2')
plt.xlim((0.0, 10.000))
plt.ylim((0.0, 10.000))
plt.show()
