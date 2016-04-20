
;; calculate the euclidean distance between two points
;; in an n-dimensional space. 
(defun distance (vec1 vec2)
  (sqrt
   (reduce #'+
           (loop for i below (length vec1) collect
                (expt (- (elt vec1 i) (elt vec2 i)) 2)))))

