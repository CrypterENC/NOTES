
	## 1.4 How do Computers Learn? 
> **What is Learning** : The acquisition of knowledge or skills **through study, experience or being taught.**

	### Deductive vs Inductive Learning

1. **Deductive Learning** : 
	- You give the **Algorithms 2 Things**:
		1. **~={red}Rules=~** (the logic/knowledge base — e.g., "IF port 22 AND failed_logins > 5 THEN alert").
		2. **~={red}Facts/Data=~** (the input — e.g., "port = 22, failed_logins = 10").
		
	- **The ~={cyan}algorithm applies the rules to the data**=~ and gives you a **~={green}conclusion/answer=~**

```markdown
Example 

|**Rule**     |"IF port == 22 AND failed_logins > 5 THEN ALERT"|
|**Data/Fact**|"port = 22, failed_logins = 10"|
|**Answer**   |"ALERT: SSH Brute Force"|
```

2. **Inductive Learning** : 
	-  You give the **Algorithms 2 Things**:
		1. **~={red}Data=~** (training samples — e.g., 10,000 network logs).
		2. **~={red}Labels/Outputs**=~ (the input — e.g., "port = 22, failed_logins = 10").
	- **The ~={cyan}algorithm studies the data and labels**=~, and **discovers/generates the rules itself** — without you telling it what rules to use.
	- **The ~={green}output is a MODEL**=~ (not a direct answer) — this model contains the learned patterns/rules

```markdown


|**You give:**        |50,000 PE files (executables), each labeled "malware" or "benign"|
|**Algorithm does:**  |Studies patterns — byte sequences, API calls, entropy, section names that correlate with malware|
|**You get:**         |A **trained model** (e.g., a Random Forest or Neural Network)|
|**Later:**           |You give the model a new, never-before-seen .exe file|
|**Model gives:**     |"This is MALWARE" (with 95% confidence)|


```

## Installing 

Download Miniconda from here -- https://anaconda.com/api/installers/Miniconda3-latest-Windows-x86_64.exe

- Then install libraries -- `conda install jupyter numpy pandas scikit-learn seaborn matplotlib jupyterlab`

- to run lab -- `jupyter lab` or `jupyter lab --no-browser`

## Testing if everything is working.

```python
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn import datasets
import matplotlib.pyplot as plt
```

## 1.6 Introduction to the Stack📜
In the next set of videos we will slowly work our way through the following notebook `0001_intro_software.ipynb.`

I will use this notebook as a base and demonstrate the basics of the libraries we will be using in this course. You should follow along on your computer.

## NumPy🎦📜👩🏽‍💻
- Numerical Python
	- The fundamental package for scientific computing
- it gives as **ndarray** (n-dimensional array)

### Importing NumPy
```python
import numpy as np  # Standard convention
```

### Core Concepts You MUST Know

#### 1. Creating Arrays
```python
# From a python list
arr = np.array([1,2,3,4,5])

#=============================================================
# Zeros, Ones, Identity
#=============================================================
zeros = np.zeros((3, 4))      # 3x4 matrix of zeros

	array([[0., 0., 0., 0.],
	       [0., 0., 0., 0.],
	       [0., 0., 0., 0.]])
	       
ones = np.ones((2, 3))        # 2x3 matrix of ones

	array([[1., 1., 1.],
	       [1., 1., 1.]])

eye = np.eye(3)               # 3x3 identity matrix

	array([[1., 0., 0.],
	       [0., 1., 0.],
	       [0., 0., 1.]])

#=============================================================
#Range of values
#=============================================================
range_arr = np.arange(0,10,2)  # from '0' to '10' with a step of '2'.

	array([0, 2, 4, 6, 8])

#=============================================================
#Random arrays (critical for ML!)
#=============================================================
rand = np.random.rand(3, 3)      # Uniform [0,1)

	array([[0.83469805, 0.12711334, 0.97709378],
	       [0.57115186, 0.91903702, 0.88583722],
	       [0.68845383, 0.84213991, 0.4950897 ]])

randn = np.random.randn(3, 3)    # Standard normal

	array([[ 1.05599473, -1.03353435,  1.86987715],
	       [-1.14992491, -0.62480301, -0.03767475],
	       [-1.97811994,  0.92250561,  0.01303398]])
	       
randint = np.random.randint(0, 100, (3, 3))  # Integers

	array([[14, 14, 15],
	       [77, 36, 67],
	       [23, 76, 22]], dtype=int32)
```

#### 2. Array Attributes
```python
arr = np.array([[1, 2, 3], [4, 5, 6]])
```

| Key              | Description              |
| ---------------- | ------------------------ |
| **arr.shape**    | (2, 3) — rows, columns   |
| **arr.size**     | 6 — total elements       |
| **arr.ndim**     | 2 — number of dimensions |
| **arr.dtype**    | int64 — data type        |
| **arr.itemsize** | 8 — bytes per element    |
#### 3. Indexing and Slicing
```python
arr = np.array([[1, 2, 3, 4],
                [5, 6, 7, 8],
                [9, 10, 11, 12]])

# Access elements
arr[0, 2]          # 3 — row 0, column 2
arr[1, :]          # [5, 6, 7, 8] — entire row 1
arr[:, 1]          # [2, 6, 10] — entire column 1
arr[0:2, 1:3]      # [[2, 3], [6, 7]] — submatrix

#Here arr[0:2, 1:3] is arr[rows, columns].

                0   1  2  3

			0	[1, 2, 3, 4]
            1   [5, 6, 7, 8]
            2   [9, 10, 11, 12]
                
    0:2 ==> Rows    that is : [1, 2, 3, 4] and [5, 6, 7, 8] 
    1:3 ==> Columns that is : 2  and  3
                              6       7

# Boolean indexing (critical for filtering)
mask = arr > 5
arr[mask]          # [6, 7, 8, 9, 10, 11, 12]
```

#### 4. Vectorized Operations (WHY NumPy is FAST)
```python
arr1 = np.array([1, 2, 3])
arr2 = np.array([4, 5, 6])

# Element-wise operations (NO LOOPS!)
arr1 + arr2        # [5, 7, 9]
arr1 * arr2        # [4, 10, 18]
arr1 ** 2          # [1, 4, 9]
np.sqrt(arr1)      # [1, 1.41, 1.73]

# Broadcasting — apply operation to entire array
arr = np.array([1, 2, 3, 4])
arr + 10           # [11, 12, 13, 14]
arr * 2            # [2, 4, 6, 8]
```

#### 5. Reshaping and Transposing
```python
arr = np.array([1, 2, 3, 4, 5, 6])

# Reshape
arr.reshape(2, 3)    # [[1, 2, 3], [4, 5, 6]]
arr.reshape(3, 2)    # [[1, 2], [3, 4], [5, 6]]

# Transpose
arr2 = np.array([[1, 2, 3], [4, 5, 6]])
arr2.T               # [[1, 4], [2, 5], [3, 6]]

# Flatten
arr2.flatten()       # [1, 2, 3, 4, 5, 6]
```

## 1.9 Matplotlib🎦📜👩🏽‍💻
### Import Matplotlib
```python
import matplotlib.pyplot as plt  # Standard alias
```

### Core Concepts You MUST Know
#### 1. Basic Line Plot
```python
import matplotlib.pyplot as plt
import numpy as np

#Data
x = np.array([1,2,3,4,5])
y = np.array([2,4,6,8,10])

#Create plot
plt.plot(x,y);
plt.title('First Line Plot using Matplotlib')
plt.xlabel('X-zxis')
plt.ylabel('Y-zxis')
```

#### 2. Figure and Axes (The OOP Way)
```python
# Create figure and axes explicitly (RECOMMENDED for complex plots)
import matplotlib.pyplot as plt
import numpy as np

#Data
x = np.array([1,2,3,4,5])
y = np.array([2,4,6,8,10])

fig, ax = plt.subplots()

ax.plot(x,y);
ax.set_xlabel('X-axis');
ax.set_ylabel('Y-axis');
ax.set_title('Line Plot');
```

#### 3. Multiple Plots on Same Figure

```python
x = np.linspace(0,10,100)
y1 = np.sin(x)    # Sine of each element in x
y2 = np.cos(x)    # Cosine of each element in x
y3 = x**2         # Square of each element in x (element-wise)

# Single Figure with multiple lines
plt.plot(x, y1, label='sin(x)', color='blue', linestyle='-')
plt.plot(x, y2, label='cos(x)', color='red', linestyle='--')
plt.plot(x, y3, label='x2', color='green', linestyle=':')

plt.xlabel('X')
plt.ylabel('Y')
plt.title('Multiple Lines')
plt.legend()
plt.grid(True, alpha=0.3)
```

![[Anatomy of Matplotlib figure.png]]

## 1.10 Pandas🎦📜👩🏽‍💻

## What is Pandas?

| **Aspect**                           | **Details**                                                                                               |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| **What it is**                       | The **#1 data manipulation library** in Python                                                            |
| **Core data structures**             | **Series** (1D) and **DataFrame** (2D — like a spreadsheet)                                               |
| **Why it matters for ML/AI**         | Data cleaning, preprocessing, feature engineering, exploratory data analysis (EDA)                        |
| **Why it matters for Cybersecurity** | Parsing logs, analyzing network traffic, processing threat intelligence feeds, handling security datasets |
| **Analogy**                          | Pandas = **Excel on steroids** with code                                                                  |

### Importing the Lib
```python
import pandas as pd  # Standard alias
import numpy as np   # Pandas builds on NumPy
```

### Core Data Structures
#### Series (1D)
```python
import pandas as pd

# Create a Series from a list
s = pd.Series([10, 20, 30, 40, 50])
print(s)

	# Output:
	# 0    10
	# 1    20
	# 2    30
	# 3    40
	# 4    50
	# dtype: int64

# Series with custom index
s = pd.Series([10, 20, 30], index=['a', 'b', 'c'])
print(s)
	# a    10
	# b    20
	# c    30
	# dtype: int64
```

#### 📍DataFrame (2D — Most Important!)
```python
# Create a DataFrame from dictionary
data = {
    'Name': ['Alice', 'Bob', 'Charlie', 'Diana'],
    'Age': [25, 30, 35, 28],
    'City': ['New York', 'London', 'Paris', 'Tokyo']
}
df = pd.DataFrame(data)
print(df)

# Output:
	#       Name  Age      City
	# 0    Alice   25  New York
	# 1      Bob   30    London
	# 2  Charlie   35     Paris
	# 3    Diana   28     Tokyo
```

### Reading Data
```python
# Read CSV file (most common)
df = pd.read_csv('network_logs.csv')

# Read Excel file
df = pd.read_excel('threat_intelligence.xlsx')

# Read JSON (API responses)
df = pd.read_json('alerts.json')

# Read from URL (threat feeds)
df = pd.read_csv('https://raw.githubusercontent.com/.../malware_data.csv')
```

### DataFrame Data Inspection
```python
# Quick overview
df.head()           # First 5 rows
df.tail()           # Last 5 rows
df.sample(10)       # Random 10 rows

# Information about dataset
df.info()           # Column names, data types, non-null counts
df.shape            # (rows, columns)
df.columns          # List of column names
df.dtypes           # Data types of each column

# Statistical summary
df.describe()       # Count, mean, std, min, 25%, 50%, 75%, max (only numeric)
df.describe(include='object')  # For categorical columns
```

## Sklearn
## What is Scikit-Learn?

|Aspect|Details|
|---|---|
|**What it is**|The **#1 machine learning library** in Python|
|**Built on**|NumPy, SciPy, Matplotlib|
|**Why it matters for ML/AI**|Provides **consistent API** for all ML algorithms — classification, regression, clustering, dimensionality reduction, preprocessing, model selection|
|**Why it matters for Cybersecurity**|Build intrusion detection systems, malware classifiers, anomaly detectors, threat prediction models|
|**Key philosophy**|**Simple, efficient, and consistent** API across all models|

### Import
```python
# Main modules
import sklearn
from sklearn import datasets
from sklearn import preprocessing
from sklearn import model_selection
from sklearn import metrics
from sklearn import ensemble
from sklearn import linear_model
from sklearn import neighbors
from sklearn import svm
from sklearn import tree
from sklearn import neural_network
from sklearn import cluster
from sklearn import decomposition
```

### SECTION 1: SKLEARN DATASETS

#### Built-in Datasets (For Learning & Testing)

|Dataset|Type|Description|Cybersecurity Use|
|---|---|---|---|
|`load_iris()`|Classification|3 species of iris flowers|Practice classification basics|
|`load_wine()`|Classification|Wine chemical composition|Practice classification|
|`load_breast_cancer()`|Classification|Cancer diagnosis|Binary classification practice|
|`load_digits()`|Classification|8x8 handwritten digits|Image classification practice|
|`fetch_california_housing()`|Regression|Housing prices|Regression practice|
|`load_diabetes()`|Regression|Diabetes progression|Regression practice|
|`make_classification()`|Synthetic|Custom classification|Generate custom IDS datasets|
|`make_regression()`|Synthetic|Custom regression|Generate custom data|
|`make_blobs()`|Synthetic|Gaussian clusters|Clustering practice|
|`make_moons()`|Synthetic|Moon-shaped clusters|Non-linear classification|
|`make_circles()`|Synthetic|Circular clusters|Non-linear classification|
|`fetch_20newsgroups()`|Text|News articles|NLP practice|
### let's load up some data with Scikit-Learn and Pandas
We will use some built-in datasets from Scikit-learn, later on we will learn to load our own data

**Note:** In the video, I use the Boston housing dataset, that dataset is no longer distrubuted with scikit-learn, so I switched to the California housing dataset. Overall the California housing dataset is better and more interesting, so it's a good change.

```python
california = datasaets.fetch_california_housing(as_frame=True)
california.feature_names

#OUTPUT
	['MedInc',
	 'HouseAge',
	 'AveRooms',
	 'AveBedrms',
	 'Population',
	 'AveOccup',
	 'Latitude',
	 'Longitude']
```

### Push our data into a pandas DataFrame for ease of use
> DataFrame is a Table like in excel, but GOATED.

```python
# Old way to push Data into DF
hosuing = pd.DataFrame(california.data, columns = california.feature_names)

# New way of pushing Data into DF using 'frame' --> as_frame=True.
housing = california.frame
```

- Look at the shape of data.

```python
housing.shape

#OUTPUT:
	(20640, 9)
```

- Show the **Tail** and **Head** of the table.

```python
housing.tail()   # Last 5
housing.head()   # First 5
```

- Get the **MEAN** 

```python
#============================================================
housing['AveRooms'].mean()  #Get mean for AveRooms Col

#OUTPUT:
	5.428999742190376
#============================================================

#============================================================	
housing.mean(axis = 0)      #Get mean for each Col

#OUTPUT:
	MedInc            3.870671
	HouseAge         28.639486
	AveRooms          5.429000
	AveBedrms         1.096675
	Population     1425.476744
	AveOccup          3.070655
	Latitude         35.631861
	Longitude      -119.569704
	MedHouseVal       2.068558
	dtype: float64
#============================================================
housing.mean(axis = 1)      #Get mean for each Row

#OUTPUT:
	0         33.562744
	1        262.094029
	2         54.061360
	3         60.454940
	4         61.045845
	            ...    
	20635     88.830077
	20636     34.017826
	20637    105.942697
	20638     76.494316
	20639    148.160729
	Length: 20640, dtype: float64
#============================================================
```

- Some **basic stats** on our numerical data

```python
housing.describe()
```

### Some Indexing

```python
housing[:3]  # gives first 3 rows of the dataset

housing[3:11:2]  #rows 3 through 11, stepping by 2, note the start in inclusive and the end is excluded (like python)
```

- Now if we want Columns in pandas we use `.iloc`

```python
housing.iloc[:3,:2] # the first 3 rows and 2 columns -- note the comma ',' which used to tell pandas that we are indexing both rows and columns

#OUTPUT
	|    MedInc|HouseAge|
	|---|------|--------|
	|0  |8.3252|41.0    |
	|1  |8.3014|21.0    |
	|2  |7.2574|52.0    |

# note we can do the same things we did before with `.iloc` as well
housing.iloc[:2]

#OUTPUT
	|   MedInc|HouseAge|AveRooms|AveBedrms|Population|AveOccup|Latitude|Longitude|MedHouseVal|
	|---|------|----|--------|-------|------|--------|-----|------- |-----|
	|0  |8.3252|41.0|6.984127|1.02381|322.0 |2.555556|37.88|-122.23 |4.526|
	|1  |8.3014|21.0|6.238137|0.97188|2401.0|2.109842|37.86|-122.22 |3.585|

```

- Now if we want Columns with there **string names** in pandas we use `.loc`

```python
housing.loc[:4, ['MedInc', 'HouseAge']]

#OUTPUT
	|    MedInc|HouseAge|
	|---|------|--------|
	|0  |8.3252|41.0    |
	|1  |8.3014|21.0    |
	|2  |7.2574|52.0    |
	|3  |5.6431|52.0    |
	|4  |3.8462|52.0    |
```