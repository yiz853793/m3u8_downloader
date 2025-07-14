import time
import threading
from threading import Thread
from typing import List, Optional, Callable, Tuple, Generator, Any
from collections import deque

class Queue:
    """
    A thread-safe queue implementation with front and back queues for prioritized processing.

    Attributes:
        front_queue (deque): Queue for high-priority items
        back_queue (deque): Queue for normal-priority items
        wrlock (threading.Lock): A lock to ensure thread-safe operations on both queues
    """

    def __init__(self):
        """
        Initialize an empty queue with a write lock.
        """
        self.front_queue = deque()
        self.back_queue = deque()
        self.wrlock = threading.Lock()

    def front_push(self, item):
        """
        Add an item to the front queue (high priority).

        Args:
            item: The item to be added to the front queue
        """
        with self.wrlock:
            self.front_queue.append(item)
    
    def back_push(self, item):
        """
        Add an item to the back queue (normal priority).

        Args:
            item: The item to be added to the back queue
        """
        with self.wrlock:
            self.back_queue.append(item)
    
    def pop(self):
        """
        Remove and return an item from the queues, prioritizing front queue items.

        Returns:
            The first item from the front queue if available, otherwise from the back queue

        Raises:
            Exception: If both queues are empty
        """
        with self.wrlock:
            if len(self.front_queue) > 0:
                return self.front_queue.popleft()
            if len(self.back_queue) > 0:
                return self.back_queue.popleft()
            raise Exception('empty')
        
    def empty(self):
        return len(self.front_queue) == 0 and len(self.back_queue) == 0

class factory:
    """
    A base factory class for creating processing pipelines with retry, delay, and error handling capabilities.

    Attributes:
        queue (Queue): The queue for holding items to be processed
        workers (int): Number of worker threads
        function (Callable): The processing function to be executed
        __last_finish (threading.Event): Event to signal when processing is finished
        __finish (threading.Event): Event to signal when factory should stop
        next_factory (factory): The next factory in the pipeline
        retries (int): Number of retry attempts for failed operations
        delay_queue (List[List]): Array of 60 slots for delayed retry items
        delay_wrlock (threading.Lock): Lock for delay queue operations
        on_retry (Callable): Callback function for retry attempts
        on_drop (Callable): Callback function for dropped items after maximum retries
    """

    def __init__(self, retries: int, function: Callable, next_factory: 'factory', threads: int = 8, 
                 on_retry: Optional[Callable[[Exception, int, object], None]] = None, 
                 on_drop: Optional[Callable[[Exception, int, object], None]] = None):
        """
        Initialize a factory with specified parameters.

        Args:
            retries: Number of retry attempts for failed operations.
            function: The processing function to be executed.
            next_factory: The next factory in the pipeline.
            threads: Number of worker threads (default is 8).
            on_retry: Callback function for retry attempts (optional).
            on_drop: Callback function for dropped items after maximum retries (optional).
        """
        self.queue = Queue()
        self.workers = threads
        self.function = function
        self.__last_finish = threading.Event()
        self.__finish = threading.Event()
        self.next_factory = next_factory
        self.retries = retries
        self.on_retry = on_retry
        self.on_drop = on_drop
        self.delay_queue = [[] for _ in range(60)]
        self.delay_wrlock = threading.Lock()
    
    def push(self, item):
        """
        Add an item to the factory's queue.

        Args:
            item: The item to be processed.
        """
        self.queue.back_push(item)
    
    def _delay_empty_(self):
        with self.delay_wrlock:
            return all(len(slot) == 0 for slot in self.delay_queue)

    def _process_delay_queue_(self):
        """
        Process the delay queue every second, moving items from delay slots to the main queue.
        Items in slot 0 are moved to the main queue, and all slots are shifted left.
        """
        while not self.__finish.is_set():
            time.sleep(1)
            with self.delay_wrlock:
                for item in self.delay_queue[0]: self.queue.front_push(item)
                self.delay_queue = self.delay_queue[1:] + [[]]

    def _one_thread_(self):
        """
        The main processing loop for a worker thread.
        """
        while True:
            # 先检查是否可以安全退出
            while self.queue.empty():
                if self._delay_empty_() and self.__last_finish.is_set():
                    return

            try:
                item = self.queue.pop()
                data, tries = item
            except Exception as e:
                continue

            try:
                answers = self.function(data)
                if self.next_factory is not None:
                    for ans in answers:
                        self.next_factory.push((ans, 0))
            except Exception as e:
                tries += 1
                if tries < self.retries :
                    if self.on_retry:
                        self.on_retry(e, tries, data)
                    delay = min(2 * tries, 60)
                    slot = delay - 1
                    self.delay_queue[slot].append((data, tries))
                else:
                    if self.on_drop:
                        self.on_drop(e, self.retries, data)
            # finally:
            #     time.sleep(1)

    def last_finish(self):
        """
        Signal that the factory has finished processing.
        """
        self.__last_finish.set()

    def start(self):
        """
        Start the factory's worker threads.
        """
        self.__last_finish.clear()
        self.__finish.clear()
        delay_thread = threading.Thread(target=self._process_delay_queue_, daemon=True)
        delay_thread.start()
        threads : List[Thread] = []
        for _ in range(self.workers):
            k = threading.Thread(target=self._one_thread_, daemon=True)
            k.start()
            threads.append(k)
        
        for thread in threads:
            thread.join()

        if self.next_factory is not None:
            self.next_factory.last_finish()
        self.__finish.set()
        delay_thread.join()

class receive_factory(factory):
    """
    A specialized factory for collecting results from the processing pipeline.
    Stores results in a list instead of passing them to next factory.

    Attributes:
        results (list): List to store the processed results
    """

    def __init__(self):
        """
        Initialize a receive factory.
        Uses a default lambda function as the processing function.
        """
        super().__init__(retries=0, function=lambda x: x, threads=0, next_factory=None)
        self.results = []
    
    def push(self, item):
        """
        Add a processed item to the results list.
        Extracts the actual item from the (item, tries) tuple.

        Args:
            item: Tuple containing the processed item and its retry count
        """
        self.results.append(item[0])

    def start(self):
        """
        Start the receive factory (does nothing in this implementation).
        """
        pass

class pipeline:
    """
    A pipeline class for orchestrating multiple processing stages.

    Attributes:
        receivefactory (receive_factory): The receive factory to collect results.
        factories (list): List of factory instances in the pipeline.
        _factory_threads (list): List of threads for the factories.
    """

    def __init__(self, *functions : Tuple[int, int, Callable, Optional[Callable], Optional[Callable]]):
        """
        Initialize a pipeline with specified functions.

        Args:
            functions: Tuple containing parameters for each processing stage.
        """
        funcs = functions[::-1]
        self.receivefactory = receive_factory()
        next_factory = self.receivefactory
        self.factories : List[factory] = []
        self._factory_threads = []
        for func_tuple in funcs:
            threads, retries, process_func, on_retry, on_drop = func_tuple
            facto = factory(retries=retries, function=process_func, threads=threads, 
                            next_factory=next_factory, on_retry=on_retry, on_drop=on_drop)
            self.factories.append(facto)
            next_factory = facto
    
    def push(self, item):
        """
        Add an item to the pipeline.

        Args:
            item: The item to be processed.
        """
        if self.factories :
            self.factories[-1].push((item, 0))

    def start(self):
        """
        Start the pipeline's processing.
        """
        self._factory_threads : List[Thread] = []
        for factory in self.factories :
            thread = threading.Thread(target=factory.start, daemon=True)
            thread.start()
            self._factory_threads.append(thread)
    
    def end(self):
        """
        Finalize the pipeline and return the results.

        Returns:
            List of processed items.
        """
        if self.factories :
            self.factories[-1].last_finish()
        
        for thread in reversed(self._factory_threads):
            thread.join()

        return self.receivefactory.results