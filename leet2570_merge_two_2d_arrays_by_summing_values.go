func mergeArrays(nums1 [][]int, nums2 [][]int) [][]int {
    numMap := make(map[int]int)
    indices := []int{}

    for _, num := range nums1 {
        numMap[num[0]] = num[1]
    }
    for _, num := range nums2 {
        numMap[num[0]] += num[1]
    }

    for i := range numMap {
        indices = append(indices, i)
    }
    sort.Ints(indices)
    merged := [][]int {}

    for _, i := range indices {
        merged = append(merged, []int{i, numMap[i]})
    }
    return merged
}